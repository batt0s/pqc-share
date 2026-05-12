"""Classic McEliece KEM Parameters

Parameter Set: mceliece348864
"""

from sage.all import GF, PolynomialRing


class McEliece348864:
    """Defines the classic mceliece parameter set and galois fields."""

    def __init__(self):
        self.m = 12
        self.n = 3488
        self.t = 64
        self.q = 2**self.m

        # for symetric crypto (shake256)
        self.l = 256
        self.sigma_1 = 16
        self.sigma_2 = 32

        # F_2[z] Polynomial Ring and f(z) irreducible polynomial
        self.R_z = PolynomialRing(GF(2), "z")
        self.z = self.R_z.gen()
        self.f_z = self.z**12 + self.z**3 + 1

        # F_q Field: F_2[z]/f(z)
        self.F_q = GF(self.q, name="z", modulus=self.f_z)

        # F_q[y] Polynomial Ring and F(y) irreducible polynomial
        self.R_y = PolynomialRing(self.F_q, "y")
        self.y = self.R_y.gen()

        # F(y) = y^64 + y^3 + y + z (Note: "z" here is the generator of field F_q)
        self.F_y = self.y**64 + self.y**3 + self.y + self.F_q.gen()

        self.F_qt = self.R_y.extension(self.F_y, "beta")
        self.beta = self.F_qt.gen()


PARAMS = McEliece348864()
