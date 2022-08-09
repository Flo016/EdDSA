from hashlib import sha512, shake_256
from secrets import randbits

class EdDSA():

    def __init__(self,  mode, phflag = False, context = "", private_key = None) -> None:
        """creates an edDSA object which can generate private/public keys, signatures and verify them."""
        self.phflag = phflag
        self.private_key = private_key
        self.mode = mode
        if type(context) == type(""):
            context = context.encode()
        if type(context) != type(b''):
            raise TypeError("Context has to be either string or Byte object.")

        self.context = context

        if mode == 1: # Ed25519
            self.prime = (2 ** 255) - 19
            self.decode = self.decode_point_ed25519
            self.calc_hash = sha512
            # Hash = SHA512
            # Curve parameters Edwards ( x² + y² = 1 + d*x²*y² )
            self.d = 37095705934669439343138083508754565189542113879843219016388785533085940283555  # -121665/121666
            self.B = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
                      46316835694926478169428394003475163141307993866256225615783033603165251855960)
            self.b = 256
            self.encoding_bits = self.b-1
            self.L = (2**252) + 27742317777372353535851937790883648493
            self.c = 3
            self.ec_calculate = ec_mont_arithmetic(self.prime, self.d)
            self.scalar_multiply = self.ec_calculate.scalarmultiply_ed25519
            self.ADD = self.ec_calculate.only_ADD
            if context != b"":
                if len(context) > 255: raise ValueError("Context too big")
                self.context=b"SigEd25519 no Ed25519 collisions"+bytes([1 if phflag else 0,len(context)])+context
            
        if mode == 2: #Ed448
            self.prime = (2 ** 448) - (2 **224) - 1 
            self.decode = self.decode_point_ed448
            self.calc_hash = shake_256
            # Hash = SHAKE256(dom4(phflag,context)||x, 114) 
            # Curve parameters Edwards ( -x² + y² = 1 + d*x²*y² )
            self.d = self.prime - 39081
            self.B = (224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710,
                      298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660)
            # parameters
            self.b = 456
            self.encoding_bits = self.b-1
            self.L = 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
            self.c = 2
            self.ec_calculate = ec_mont_arithmetic(self.prime, self.d)
            self.scalar_multiply = self.ec_calculate.scalarmultiply_ed448
            self.ADD = self.ec_calculate.only_ADD_448
            if context != b'':
                if len(context) > 255: raise ValueError("Context too big")
                self.context=b"SigEd448"+bytes([1 if phflag else 0,len(context)])+context

    def key_generation(self):
        if self.private_key is None:
            private = randbits(self.b)
            private = private.to_bytes(private.bit_length(), 'big')
        else: 
            private = self.private_key
        hashed_key = list(bytes.fromhex(self.calc_hash_value(private)))
        hashed_key = self.prep_hashed_key(hashed_key)
        secret_scalar = int.from_bytes(bytes(hashed_key[:self.b//8]), 'little')
        public_key = self.encode(self.scalar_multiply(secret_scalar, self.B))
        prefix = hashed_key[self.b//8:]
        return private, public_key, secret_scalar, prefix


    def sign(self, message: bytes):
        private_key, public_key, secret_scalar, prefix = self.key_generation()
        message = self.calc_hash_message(message)
        r = int.from_bytes(bytes.fromhex(self.calc_hash_value(self.context + bytes(prefix) + message)), 'little') % self.L
        R = self.encode(self.scalar_multiply(r, self.B))        
        k = int.from_bytes(bytes.fromhex(self.calc_hash_value(self.context + R + public_key + message)), 'little') % self.L
        S = (r + k*secret_scalar) % self.L
        signature = R + int.to_bytes(S, self.b//8, 'little')

        return signature, public_key, private_key

    def verify(self, signature:bytes, public_key:bytes, message:bytes):
        # recover public values
        R = bytes(list(signature)[:self.b//8])
        S = int.from_bytes(bytes(list(signature)[self.b//8:]), 'little')
        A = self.decode(public_key)
        R_point = self.decode(R)
        message = self.calc_hash_message(message)
        k = int.from_bytes(bytes.fromhex(self.calc_hash_value(self.context + R + public_key + message)), 'little')

        # verify value integrity
        if k % self.L == 0 or S % self.L == 0 or not self.point_exists(R_point):
            return False
        value1 = self.scalar_multiply(S, self.B)
        value2 = self.ADD(self.scalar_multiply(k, A), R_point)
        if value1 == value2:
            return True
        return False

    def mod_inverse(self, number):
        return pow(number, self.prime-2, self.prime)

    def encode(self, point):
        return int.to_bytes(point[1] | ((point[0] & 1) << self.encoding_bits), self.b//8, "little")

    def decode_point_ed25519(self, byte_encoding):
        y = int.from_bytes(byte_encoding, "little")
        x_sign = y >> self.b-1
        y &= (1 << self.b-1) - 1
        x2 = ((y*y-1) * self.mod_inverse(self.d*y*y+1)) % self.prime

        # Compute square root of x2
        x = pow(x2, (self.prime+3) // 8, self.prime)
        if ((x*x - x2) % self.prime) != 0:
            x = x * pow(2, (self.prime-1) // 4, self.prime) % self.prime

        if (x & 1) != x_sign:
            x = self.prime - x % self.prime
        return (x, y)

    def decode_point_ed448(self, bytecode):
        y = int.from_bytes(bytecode, "little")
        x_sign = y >> self.b-1
        y &= (1 << self.b-1) - 1
        u = ((y ** 2) - 1) % self.prime
        v = ((self.d * y**2) -1) % self.prime

        # compte squareroot of u / v
        x = pow(u, 3, self.prime) * v * pow( pow(u, 5, self.prime) * pow(v, 3, self.prime), (self.prime-3)//4, self.prime) % self.prime
        if (x & 1) != x_sign:
            x = self.prime - x % self.prime
        return (x, y)

    def prep_hashed_key(self, hashed_key):
        a = bin(hashed_key[0])[2:]
        while len(a) < self.c:
            a = "0" + a
        a = a[:-self.c] + ("0" * self.c)
        hashed_key[0] = int(a, 2)
        # set bits for ed25519
        if self.mode == 1:
            if hashed_key[(self.b//8)-1] >= 128:
                hashed_key[(self.b//8)-1] -= 128
            if hashed_key[(self.b//8)-1] < 64:
                hashed_key[(self.b//8)-1] += 64
        # set bits for ed448
        else:
            hashed_key[(self.b//8)-1] = 0
            if hashed_key[(self.b//8)-2] < 128:
                hashed_key[(self.b//8)-2] += 128
        return hashed_key

    def calc_hash_value(self, data):
        if self.mode == 1:
            return self.calc_hash(data).hexdigest()[2:]
        else: 
            return self.calc_hash(data).hexdigest((self.b//8)*2)[2:]
        
    def calc_hash_message(self, message: bytes):
        if self.phflag:
            if self.mode == 1:
                message = self.calc_hash(message).digest()
            else: 
                message = self.calc_hash(message).digest(64)
        return message

    def point_exists(self, point):
        y = point[1]
        u = ((y ** 2) - 1) % self.prime
        v = ((self.d * y**2) -1) % self.prime
        x = u * pow(v, -1, self.prime) % self.prime

        xx = pow(x, (self.prime-1)//2, self.prime)
        if xx == 1 and not (point == (0, 0)):
            return True
        return False


class ec_mont_arithmetic():
    def __init__(self, prime, d):
        self.p = prime
        self.d = d

    def ADD_25519(self, point1, point2):
        A = (point1[1] - point1[0]) * (point2[1] - point2[0]) % self.p
        B = (point1[1] + point1[0]) * (point2[1] + point2[0]) % self.p
        C = point1[3] * 2 * self.d * point2[3] % self.p
        D = point1[2] * 2 * point2[2] % self.p
        E = B - A % self.p
        F = D - C  % self.p
        G = D + C % self.p
        H = B + A % self.p
        X3 = E * F % self.p
        Y3 = G * H % self.p
        Z3 = F * G % self.p
        T3 = E * H % self.p

        return (X3, Y3, Z3, T3)

    def ADD_448(self, point1, point2):
        A = point1[2] * point2[2] % self.p
        B = A**2 % self.p
        C = point1[0] * point2[0] % self.p
        D = point1[1] * point2[1] % self.p
        E = self.d * C * D % self.p
        F = B - E % self.p
        G = B + E % self.p
        H = (point1[0] + point1[1]) * (point2[0] + point2[1])  % self.p
        X3 = A * F * (H - C - D) % self.p
        Y3 = A * G * (D - C) % self.p
        Z3 = F * G % self.p
        return (X3, Y3, Z3)

    def only_ADD(self, point1, point2):

        point1 = (point1[0], point1[1], 1, point1[0]*point1[1])
        point2 = (point2[0], point2[1], 1, point2[0]*point2[1])

        A = (point1[1] - point1[0]) * (point2[1] - point2[0]) % self.p
        B = (point1[1] + point1[0]) * (point2[1] + point2[0]) % self.p
        C = point1[3] * 2 * self.d * point2[3] % self.p
        D = point1[2] * 2 * point2[2] % self.p
        E = B - A % self.p
        F = D - C  % self.p
        G = D + C % self.p
        H = B + A % self.p
        X3 = E * F % self.p
        Y3 = G * H % self.p
        Z3 = F * G % self.p

        X3 = X3* pow(Z3, self.p-2, self.p) % self.p
        Y3 = Y3 * pow(Z3, self.p-2, self.p) % self.p

        return (X3, Y3)

    def only_ADD_448(self, point1, point2):
        point1 = (point1[0], point1[1], 1)
        point2 = (point2[0], point2[1], 1)

        A = point1[2] * point2[2] % self.p
        B = A**2 % self.p
        C = point1[0] * point2[0] % self.p
        D = point1[1] * point2[1] % self.p
        E = self.d * C * D % self.p
        F = B - E % self.p
        G = B + E % self.p
        H = (point1[0] + point1[1]) * (point2[0] + point2[1])  % self.p
        X3 = A * F * (H - C - D) % self.p
        Y3 = A * G * (D - C) % self.p
        Z3 = F * G % self.p

        X3 = X3 * pow(Z3, self.p-2, self.p) % self.p
        Y3 = Y3 * pow(Z3, self.p-2, self.p) % self.p
        return(X3, Y3)
    
    def Double_and_Add_Always_448(self, s: int, P):
        
        Q = (0, 1, 1)  # Neutral element
        while s > 0:
            if s & 1:
                Q = self.ADD_448(Q, P)
            else: 
                T = self.ADD_448(Q, P)
            P = self.ADD_448(P, P)
            s >>= 1
        return Q

        """
        Montgommery Ladder
        x0, x1  = P, (self.DBL_448(P))
        while n > 0:
            if n & 1:
                x0, x1  = (self.ADD_448(x0, x0)), (self.ADD_448(x0, x1))
            else:
                x0, x1 = (self.ADD_448(x0, x1)), (self.ADD_448(x1, x1))
            n >>= 1
        return x0 #x0 is next answer
        """
    def Double_and_Add_Always_25519(self, n: int, P):

        Q = (0, 1, 1, 0)  # Neutral element
        while n > 0:
            if n & 1:
                Q = self.ADD_25519(Q, P)
            else: 
                T = self.ADD_25519(Q, P)
            P = self.ADD_25519(P, P)
            n >>= 1
        return Q

        """
        Montgommery Ladder
        x0, x1  = (0,1,1,0), P 
        while n > 0:
            if n & 1:
                x0, x1  = (self.ADD_25519(x0, x0)), (self.ADD_25519(x0, x1))
            else:
                x0, x1 = (self.ADD_25519(x0, x1)), (self.ADD_25519(x1, x1))
            n >>= 1
        return x0 #x1 is next answer
        """

    def scalarmultiply_ed448(self, n, point: tuple): # (x, y tuple)

        # turn into projective coordinates
        projective_point = (point[0], point[1], 1)

        # get projective coordinate scalar multiplication
        point_p = self.Double_and_Add_Always_448(n, projective_point)

        # turn into affine coordinates
        qx= point_p[0] * pow(point_p[2], self.p-2, self.p) % self.p
        qy= point_p[1] * pow(point_p[2], self.p-2, self.p) % self.p

        return (qx, qy)

    def scalarmultiply_ed25519(self, n, point: tuple): # (x, y tuple)

        # turn into projective coordinates
        projective_point = (point[0], point[1], 1, point[0]*point[1])

        # get projective coordinate scalar multiplication
        point_p = self.Double_and_Add_Always_25519(n, projective_point)

        # turn into affine coordinates
        qx= point_p[0] * pow(point_p[2], self.p-2, self.p) % self.p
        qy= point_p[1] * pow(point_p[2], self.p-2, self.p) % self.p

        return (qx, qy)