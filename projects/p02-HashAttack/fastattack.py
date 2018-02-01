"""
SHA-1 Hash Attack Experiments
Braden Hitchcock
CS 465 - Computer Security
Brigham Young University
02.02.2018

This file contains the experiments that generated results for analyzing hash attacks and evaluating the security of
systems that only use 8 to 32 bit hashes in defending against pre-image and collision attacks.
"""
from shawrapper import SHA1Wrapper
import matplotlib.pyplot as plt
import numpy as np
import math
import logging
import sys


logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)-8s:: %(message)s',
                    )

verbose = False
collision_plot = "./data/collision.png"
pre_image_plot = "./data/pre_image.png"


class WordGenerator(object):
    def __init__(self):
        self.alpha = "abcdefghijklmnopqrstuvwxyz"

    def get_word(self):
        w = ""
        for i in range(np.random.randint(1,10)):
            w = w + self.alpha[np.random.randint(1,len(self.alpha))]
        return w


def collision_attack_worker(bit_size, averages):
    """
    Worker implementation for finding a collision between two hashes
    :param bit_size: The bit size of the hash
    :param averages: A list of all averages this function can write the result to
    """
    hashes = {}
    g = WordGenerator()
    w = g.get_word()
    h = SHA1Wrapper.hash(w, bit_size)
    while h not in hashes.keys() or w == hashes[h]:
        hashes[h] = w
        w = g.get_word()
        h = SHA1Wrapper.hash(w, bit_size)
    if verbose:
        logging.debug("Found collision: (%d, %d, %s, %s)", len(hashes), h, hashes[h], w)
    averages.append(len(hashes))


def pre_image_attack_worker(bit_size, averages):
    """
    Worker implementation for finding a pre-image between two hashes
    :param bit_size: The bit size of the hash
    :param averages: A list of all averages this function can write the result to
    """
    g = WordGenerator()
    w = g.get_word()
    wh = SHA1Wrapper.hash(w, bit_size)
    c = g.get_word()
    ch = SHA1Wrapper.hash(c, bit_size)
    count = 1
    while ch != wh or c == w:
        c = g.get_word()
        ch = SHA1Wrapper.hash(c, bit_size)
        count = count + 1
    if verbose:
        logging.debug("Found pre-image: (%d, %d, %s, %s)", count, ch, w, c)
    averages.append(count)


def collision_attack(bit_size, rounds=50):
    """
    Conducts a collision attack on hash values with the provided bit size. The attack will repeat itself 'rounds'
    number of times to gather accurate average-able data

    :param bit_size: The size in bits the hash should be
    :param rounds: The number of rounds to run the experiment. Default is 50
    :return: The average attempt count for the collision attacks
    """
    logging.debug("Beginning collision attack at %d bits", bit_size)

    averages = list()

    for i in range(rounds):
        collision_attack_worker(bit_size, averages)

    return sum(averages)/len(averages)


def pre_image_attack(bit_size, rounds=50):
    """
    Conducts a pre-image attack on hash values with the provided bit size. The attack repeats itself 'rounds'
    number of times.

    :param bit_size: The size in bits the hash should be
    :param rounds: The number of rounds to run the experiment. Default is 50.
    :return: A populated ExperimentalResults object
    """

    logging.debug("Beginning pre-image attack at %d bits", bit_size)

    averages = list()

    # Conduct the experiment for i rounds
    for i in range(rounds):
        pre_image_attack_worker(bit_size, averages)

    return sum(averages)/len(averages)


def plot_results_against_theoretical(average_results, theoretical_results, out_png_file):
    """
    Given files containing averaged and theoretical data, this plots the two against each other and writes them to
    the output PNG file.

    :param average_results: CSV file containing the averaged, experimental data
    :param theoretical_results: CSV file containing the theoretical data
    :param out_png_file: The path to the PNG file to write the plot to
    """
    logging.debug("Plotting graphs")
    plt.figure(1)
    plt.plot([i for i,j in average_results], [j for i, j in average_results], 'b-')
    plt.plot([i for i,j in theoretical_results], [j for i, j in theoretical_results], 'r-')
    plt.axis([0,average_results[-1][0],0,max(average_results[-1][1], theoretical_results[-1][1])])
    plt.xlabel("Bit Size")
    plt.ylabel("Collision Attack Attempts")
    plt.savefig(out_png_file)


def generate_theoretical_results(bit_limit):
    """
    Given the settings above, it generates theoretical outputs based on the number of attempts collisions and pre-images
    are supposed to be able to be found based on the bit size of the hash
    :returns Two lists, the first for collisions, the second for pre-image
    """
    logging.debug("Generating theoretical results")
    # Generate collision
    r = np.arange(1.0,float(bit_limit) + 1, 1)
    collisions = list()
    fun = lambda x : math.pow(2, x / 2.0)
    for i in r:
        collisions.append((i, fun(i)))
    # Generate pre-image
    pre_images = list()
    fun = lambda x : math.pow(2, x)
    for i in r:
        pre_images.append((i, fun(i)))
    return collisions, pre_images


def main(bit_sizes, rounds):

    # Calculate theoretical values and write them to a file
    theoretical_collisions, theoretical_pre_images = generate_theoretical_results(bit_sizes[-1])

    # Begin collision attacks
    results = list()
    for bs in bit_sizes:
        results.append((bs, collision_attack(bit_size=bs, rounds=rounds)))
    plot_results_against_theoretical(average_results=results,
                                     theoretical_results=theoretical_collisions,
                                     out_png_file=collision_plot)

    # Begin pre-image attacks
    results = list()
    for bs in bit_sizes:
        results.append((bs, pre_image_attack(bit_size=bs, rounds=rounds)))
    plot_results_against_theoretical(average_results=results,
                                     theoretical_results=theoretical_pre_images,
                                     out_png_file=pre_image_plot)



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Usage:",sys.argv[0],"bit,sizes,as,list rounds"
        sys.exit(0)
    if len(sys.argv) > 3 and sys.argv[3] == "-v":
        verbose = True
    main([int(arg) for arg in sys.argv[1].split(",")],int( sys.argv[2]))
