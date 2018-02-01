"""
SHA-1 Hash Attack Experiments
Braden Hitchcock
CS 465 - Computer Security
Brigham Young University
02.02.2018

This file contains the experiments that generated results for analyzing hash attacks and evaluating the security of
systems that only use 8 to 32 bit hashes in defending against pre-image and collision attacks.

NOTE: The Markov Sentence Generator is used to compute string values to expirement with. The code was written as open
source software and is available under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 on GitHub at
https://github.com/hrs/markov-sentence-generator
"""
from shawrapper import SHA1Wrapper
from markovsentencegen import generator
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import math
import threading
import logging
import os

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )


settings = {
    "markov_file":"./markovsentencegen/portrait-of-the-artist.txt",
    "markov_length": 1,
    "dictionary_file":"./data/words.txt",
    "theoretical_csv_file_collision":"./data/collision_theory.csv",
    "theoretical_csv_file_pre_image":"./data/pre_image_theory.csv",
    "average_csv_file_collision":"./data/collision_average.csv",
    "average_csv_file_pre_image":"./data/pre_image_average.csv",
    "collision_plot":"./data/collision.png",
    "pre_image_plot":"./data/pre_image.png",
    "collision_bit_sizes":[8,14,16,22,26],
    "pre_image_bit_sizes":[8,14,16,22,26]
}


class SentenceGenerator(object):
    """
    Thread-safe wrapper for the Markov Sentence Generator
    """
    def __init__(self):
        self.lock = threading.Lock()
        generator.buildMapping(generator.wordlist(settings["markov_file"]), settings["markov_length"])

    def get_sentence(self):
        self.lock.acquire()
        sentence = generator.genSentence(settings["markov_length"])
        self.lock.release()
        return sentence


class ComboWordFinder(object):
    """
    Thread-safe object that can retrieve a random word or words from the dictionary
    """
    def __init__(self, dictionary_file):
        self.words = []
        if os.path.exists(dictionary_file):
            with open(dictionary_file, "r") as dictionary:
                for line in dictionary:
                    self.words.append(line.rstrip().lower())
                dictionary.close()
                self.size = len(self.words)

    def get_sentence(self):
        num_words = np.random.randint(1,4)
        s = ""
        for i in range(num_words):
            word_index = np.random.randint(0, self.size)
            s = s + self.words[word_index]
        return s


class ExperimentResults(object):
    """
    Class used to collect summative data after experiments are conducted.
    The results are stored in a Pandas DataFrame object. This is a thread safe class.
    """
    def __init__(self, bit_size):
        self.bit_size = bit_size
        self.results = pd.DataFrame(columns=[
            "attempt_counts",
            "hash",
            "sentence",
            "collision"
        ])
        self.lock = threading.Lock()
        self.__written = False

    def write(self, out_file):
        self.lock.acquire()
        self.results.to_csv(out_file, index=False)
        self.__written = True
        self.lock.release()

    def read(self, in_file):
        self.lock.acquire()
        self.results = pd.read_csv(in_file)
        self.lock.release()

    def append(self, counts, result_hash, sentence, collision):
        self.lock.acquire()
        self.results.loc[self.results.size] = [counts, result_hash, sentence, collision]
        self.lock.release()

    def get_average_attempts(self):
        self.lock.acquire()
        r = self.results["attempt_counts"].mean()
        self.lock.release()
        return r


def collision_attack_worker(bit_size, sentence_generator, results):
    """
    Worker thread implementation for finding a collision between two hashes given the bit size of
    the hash, the generator used to create sentences, and the results object this thread should update
    upon completion.

    :param bit_size: The bit size of the hash
    :param sentence_generator: The SentenceGenerator object that wraps the Markov Sentence Generator
    :param results: The ExperimentalResults object to update upon completion
    """
    hashes = {}
    collision = sentence_generator.get_sentence()
    collision_hash = SHA1Wrapper.hash(collision, bit_size)
    while collision_hash not in hashes.keys():
        hashes[collision_hash] = collision
        collision = sentence_generator.get_sentence()
        collision_hash = SHA1Wrapper.hash(collision, bit_size)
    logging.debug("Found collision: (%d, %d, %s, %s)", len(hashes), collision_hash,
                  hashes[collision_hash], collision)
    results.append(len(hashes), collision_hash, hashes[collision_hash], collision)


def pre_image_attack_worker(bit_size, sentence_generator, results):
    """
    Worker thread implementation for finding a pre-image between two hashes given the bit size of
    the hash, the generator used to create sentences, and the results object this thread should update
    upon completion.

    :param bit_size: The bit size of the hash
    :param sentence_generator: The SentenceGenerator object that wraps the Markov Sentence Generator
    :param results: The ExperimentalResults object to update upon completion
    """
    sentence = sentence_generator.get_sentence()
    sentence_hash = SHA1Wrapper.hash(sentence, bit_size)
    collision = sentence_generator.get_sentence()
    collision_hash = SHA1Wrapper.hash(collision, bit_size)
    counts = 1
    while collision_hash != sentence_hash or sentence == collision:
        collision = sentence_generator.get_sentence()
        collision_hash = SHA1Wrapper.hash(collision, bit_size)
        counts = counts + 1
    logging.debug("Found pre-image: (%d, %d, %s, %s)", counts, sentence_hash, sentence, collision)
    results.append(counts, sentence_hash, sentence, collision)


def collision_attack(bit_size, sentence_generator, rounds=50):
    """
    Conducts a collision attack on hash values with the provided bit size. The attack will repeat itself 'rounds'
    number of times to gather accurate average-able data

    :param bit_size: The size in bits the hash should be
    :param sentence_generator: The word generator for the tasks
    :param rounds: The number of rounds to run the experiment. Default is 50
    :return: A populated ExperimentalResults object
    """
    logging.debug("Beginning collision attack at %d bits", bit_size)
    # Create a results object
    results = ExperimentResults(bit_size)

    # List to keep track of the workers
    workers = list()

    # Conduct the experiment for i rounds
    logging.debug("Generating and starting threads")
    for i in range(rounds):
        t = threading.Thread(target=collision_attack_worker, args=(bit_size, sentence_generator, results))
        workers.append(t)
        t.start()

    for i in range(rounds):
        workers[i].join()
        logging.debug("Collected thread %d", i)

    logging.debug("Collected threads")
    logging.debug("Finishing collision attack at %d bits", bit_size)
    return results


def pre_image_attack(bit_size, sentence_generator, rounds=50):
    """
    Conducts a pre-image attack on hash values with the provided bit size. The attack repeats itself 'rounds'
    number of times.

    :param bit_size: The size in bits the hash should be
    :param sentence_generator: The object that randomly produces sentences to hash.
    :param rounds: The number of rounds to run the experiment. Default is 50.
    :return: A populated ExperimentalResults object
    """
    logging.debug("Beginning pre-image attack at %d bits", bit_size)
    # Create a results object
    results = ExperimentResults(bit_size)

    # List to keep track of the workers
    workers = list()

    logging.debug("Creating and starting threads")
    # Conduct the experiment for i rounds
    for i in range(rounds):
        t = threading.Thread(target=pre_image_attack_worker, args=(bit_size, sentence_generator, results))
        workers.append(t)
        t.start()

    for i in range(rounds):
        workers[i].join()
        logging.debug("Collected thread %d", i)

    logging.debug("Collected threads")
    logging.debug("Finished pre-image attack at %d bits", bit_size)
    return results


def write_average_experimental_to_csv(result_list, csv_file):
    """
    Takes a populated list of DataFrames, averages the values for each experiment, and then writes the averages
    to a CSV file to be plotted later.

    :param result_list: A list of ExperimentalResult objects that have been populated with data
    :param csv_file: The file to write the averages to
    """
    logging.debug("Writing average experimental values for %d bits", result_list[0].bit_size)
    df = pd.DataFrame(columns=["bit_size","average_attempts"])
    for result in result_list:
        average = result.get_average_attempts()
        df.loc[df.size] = [result.bit_size, average]
    df.to_csv(csv_file, index=False)


def plot_results_against_theoretical(average_csv_data, theory_csv_data, out_png_file):
    """
    Given files containing averaged and theoretical data, this plots the two against each other and writes them to
    the output PNG file.

    :param average_csv_data: CSV file containing the averaged, experimental data
    :param theory_csv_data: CSV file containing the theoretical data
    :param out_png_file: The path to the PNG file to write the plot to
    """
    logging.debug("Plotting graphs")
    data = pd.read_csv(average_csv_data)
    data2 = pd.read_csv(theory_csv_data)
    plt.figure()
    ax = data.plot(x='bit_size', y='average_attempts')
    data2.plot(ax=ax, x='bit_size', y='theoretical_attempts')
    ax.set_xlabel("Bit Size")
    ax.set_ylabel("Collision Attack Attempts")
    figure = ax.get_figure()
    figure.savefig(out_png_file)


def generate_theoretical_results():
    """
    Given the settings above, it generates theoretical outputs based on the number of attempts collisions and pre-images
    are supposed to be able to be found based on the bit size of the hash. This function writes the results to CSV files
    to be used later.
    """
    logging.debug("Generating theoretical results")
    # Generate collision
    df = pd.DataFrame(columns=["bit_size","theoretical_attempts"])
    r = np.arange(1,settings["collision_bit_sizes"][-1],1)
    fun = lambda x : math.pow(2.0, float(x / 2.0))
    for i in r:
        df.loc[df.size] = [i, fun(i)]
    df.to_csv(settings["theoretical_csv_file_collision"], index=False)

    # Generate pre-image
    df = pd.DataFrame(columns=["bit_size","theoretical_attempts"])
    r = np.arange(1, settings["pre_image_bit_sizes"][-1],1)
    fun = lambda x: math.pow(2, x)
    for i in r:
        df.loc[df.size] = [i, fun(i)]
    df.to_csv(settings["theoretical_csv_file_pre_image"], index=False)


def main():
    # Use a file of words to generate a mapping to create sentences to test hashing against
    markov_generator = SentenceGenerator()

    # Allow for use of a word generator
    word_generator = ComboWordFinder(settings["dictionary_file"])

    # Calculate theoretical values and write them to a file
    generate_theoretical_results()

    # Begin collision attacks
    results = list()
    for bs in settings["collision_bit_sizes"]:
        results.append(collision_attack(bit_size=bs, sentence_generator=word_generator))
    write_average_experimental_to_csv(result_list=results, csv_file=settings["average_csv_file_collision"])
    plot_results_against_theoretical(average_csv_data=settings["average_csv_file_collision"],
                                     theory_csv_data=settings["theoretical_csv_file_collision"],
                                     out_png_file=settings["collision_plot"])

    # Begin pre-image attacks
    results = list()
    for bs in settings["pre_image_bit_sizes"]:
        results.append(pre_image_attack(bit_size=bs, sentence_generator=word_generator))
    write_average_experimental_to_csv(result_list=results, csv_file=settings["average_csv_file_pre_image"])
    plot_results_against_theoretical(average_csv_data=settings["average_csv_file_pre_image"],
                                     theory_csv_data=settings["theoretical_csv_file_pre_image"],
                                     out_png_file=settings["pre_image_plot"])



if __name__ == "__main__":
    main()