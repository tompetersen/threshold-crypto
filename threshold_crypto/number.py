import functools
import operator
from typing import List

from Crypto.PublicKey import ECC
from Crypto.Random import random


def ecc_sum(points: List[ECC.EccPoint]):
    """ Compute the sum of a list of EccPoints. """
    if len(points) == 0:
        return None
    elif len(points) == 1:
        return points[0].copy()
    else:
        result = points[0].copy()
        for point in points[1:]:
            result += point

        return result


def random_in_range(a: int, b: int) -> int:
    """ Return a random number r with a <= r <= b. """
    return random.randint(a, b)


def prime_mod_inv(x: int, p: int) -> int:
    """ Compute the modular inverse of x in the finite field Z_p. """
    return pow(x, p - 2, p)  # Fermats little theorem


def prod(factors: [int]) -> int:
    """ Compute the product of a list of integers. """
    return functools.reduce(operator.mul, factors, 1)


class PolynomMod:

    @staticmethod
    def create_random_polynom(absolute_term: int, degree: int, q: int):
        coefficients = [absolute_term]
        coefficients.extend([random_in_range(1, q - 1) for _ in range(0, degree)])

        return PolynomMod(coefficients, q)

    def __init__(self, coefficients: [int], q: int):
        # Make sure that the highest degree coefficient is set.
        # An alternative would be to strip trailing zero elements.
        assert coefficients[-1] != 0

        self._coefficients = coefficients
        self._q = q

    @property
    def q(self) -> int:
        return self._q

    @property
    def degree(self):
        return len(self._coefficients) - 1

    @property
    def coefficients(self) -> list:
        return self._coefficients

    def evaluate(self, x: int) -> int:
        evaluated = ((self._coefficients[j] * pow(x, j)) for j in range(0, self.degree + 1))
        return sum(evaluated) % self.q

    def __str__(self):
        c_list = ["%d*x^%d " % (c, i) for (i, c) in enumerate(self._coefficients)]
        return "Polynom of degree %d: f(x) = %s" % (self.degree, " + ".join(c_list))
