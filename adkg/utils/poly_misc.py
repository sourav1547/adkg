# Helper Functions
def lagrange_at_x(s, j, x, ZR):
    s = sorted(s)
    assert j in s
    l1 = [x - jj for jj in s if jj != j]
    l2 = [j - jj for jj in s if jj != j]
    (num, den) = (ZR(1), ZR(1))
    for item in l1:
        num *= item
    for item in l2:
        den *= item
    return num / den


def interpolate_g1_at_x(coords, x, G1, ZR, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])
    out = G1.identity()
    for i in range(order):
        out *= (sortedcoords[i][1] ** (lagrange_at_x(s, xs[i], x, ZR)))
    return out
