from sage.all import *

# Параметры конечного поля и эллиптической кривой
prime_field_modulus_q = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd

curve_param_A = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
curve_param_B = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

G_x = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
G_y = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

# Создание конечного поля и эллиптической кривой
F = GF(prime_field_modulus_q)
E = EllipticCurve(F, [curve_param_A, curve_param_B])

# Проверки на простоту параметров и поля
print(f"Проверка: модуль конечного поля q является простым? {is_prime(prime_field_modulus_q)}")

# Порядок группы точек кривой
curve_order = E.order()
print(f"Порядок группы точек эллиптической кривой: {curve_order}")
print(f"Длина порядка кривой в битах: {curve_order.nbits()}")
print(f"Проверка: порядок кривой является простым? {curve_order.is_prime()}")

# Создание базовой точки генератора
G = E.point((G_x, G_y))

# Порядок генеративной точки и его битовая длина
order = G.order()
order_bits = order.nbits()

print(f"Порядок базовой генеративной точки: {order}")
print(f"Длина порядка генеративной точки в битах: {order_bits}")
print(f"Проверка: порядок генеративной точки является простым? {order.is_prime()}")

factors = order.factor()

factor_str = "n = " + " * ".join([f"{p}^{e}" for p, e in factors])
print(factor_str)

mul_small_prime = 1
for p, e in factors[:]:
    mul_small_prime *= p**e
    n_i = order//(p^e)
    print("n_i ", n_i)
    print("n_i bits", n_i.nbits())

print(f"Длина произведения малых делителей в битах: {mul_small_prime.nbits()}")

large_prime = 7072010737074051173701300310820071551428959987622994965153676442076542799542912293
print(f"Длина большого делителя в битах: {large_prime.bit_length()}")