from md5 import md5


def test_prcomputed():
    assert md5('a') == '0cc175b9c0f1b6a831c399e269772661'
    assert md5('ab') == '187ef4436122d1cc2f40dc2b92f0eba0'
    assert md5('abc') == '900150983cd24fb0d6963f7d28e17f72'
    assert md5('abcd') == 'e2fc714c4727ee9395f324cd2e7f331f'
