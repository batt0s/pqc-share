"""Classic McEliece KEM Parameters

Parameter Set: mceliece348864
"""

from sage.all import GF, PolynomialRing

# Parameters from McEliece Specifications
NIST_CONFIGS = {
    1: {
        "name": "mceliece348864",
        "m": 12,
        "n": 3488,
        "t": 64,
        "f_z_func": lambda z: z**12 + z**3 + 1,
        "F_y_func": lambda y, z: y**64 + y**3 + y + z,
    },
    3: {
        "name": "mceliece460896",
        "m": 13,
        "n": 4608,
        "t": 96,
        "f_z_func": lambda z: z**13 + z**4 + z**3 + z + 1,
        "F_y_func": lambda y, z: y**96 + y**10 + y**9 + y**6 + 1,
    },
    5: {
        "name": "mceliece6688128",
        "m": 13,
        "n": 6688,
        "t": 128,
        "f_z_func": lambda z: z**13 + z**4 + z**3 + z + 1,
        "F_y_func": lambda y, z: y**128 + y**7 + y**2 + y + 1,
    },
}


class McElieceParams:
    """Defines the classic mceliece parameter set and galois fields."""

    def __init__(self, level: int = 1):
        if level not in NIST_CONFIGS:
            raise ValueError(
                f"Invalid level: {level}. Must be one of {list(NIST_CONFIGS.keys())}"
            )

        cfg = NIST_CONFIGS[level]
        self.level = level

        self.m = cfg["m"]
        self.n = cfg["n"]
        self.t = cfg["t"]
        self.q = 2**self.m
        self.k = self.n - (self.m * self.t)

        # for symetric crypto (shake256)
        self.l = 256
        self.sigma_1 = 16
        self.sigma_2 = 32

        # F_2[z] Polynomial Ring and f(z) irreducible polynomial
        self.R_z = PolynomialRing(GF(2), "z")
        self.z = self.R_z.gen()
        self.f_z = cfg["f_z_func"](self.z)

        # F_q Field: F_2[z]/f(z)
        self.F_q = GF(self.q, name="z", modulus=self.f_z)

        # F_q[y] Polynomial Ring and F(y) irreducible polynomial
        self.R_y = PolynomialRing(self.F_q, "y")
        self.y = self.R_y.gen()

        # F(y) = y^64 + y^3 + y + z (Note: "z" here is the generator of field F_q)
        self.F_y = cfg["F_y_func"](self.y, self.F_q.gen())

        self.F_qt = self.R_y.extension(self.F_y, "beta")
        self.beta = self.F_qt.gen()


# PARAMS = McElieceParams(level=1)
