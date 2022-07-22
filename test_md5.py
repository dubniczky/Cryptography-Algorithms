from md5 import md5


def test_prcomputed():
    assert md5('a') == '0cc175b9c0f1b6a831c399e269772661'
    assert md5('ab') == '187ef4436122d1cc2f40dc2b92f0eba0'
    assert md5('abc') == '900150983cd24fb0d6963f7d28e17f72'
    assert md5('abcd') == 'e2fc714c4727ee9395f324cd2e7f331f'


def test_longtext():
    text = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse et justo dapibus, varius magna a, commodo quam. Phasellus mollis egestas pretium. Phasellus ac semper felis. Mauris tellus neque, scelerisque blandit ex ac, ullamcorper mattis augue. Vestibulum hendrerit eros suscipit mi congue, ac laoreet eros dapibus. Aliquam vitae nibh pulvinar, interdum felis at, ornare metus. Mauris consectetur mi vel tellus euismod, at scelerisque nisl porttitor. Donec id velit dapibus, interdum magna ac, viverra erat. Proin placerat consectetur leo id volutpat. Vestibulum ac mi sed neque facilisis feugiat a a tortor. Integer iaculis diam quam, ultricies commodo velit dapibus ac. Donec vitae sem ipsum. Phasellus vehicula quam et lectus iaculis, at efficitur lacus convallis. Pellentesque condimentum enim orci, et tempus erat viverra a. Duis gravida velit quam, in lobortis elit congue commodo.'
    assert md5(text) == 'b1de9e05ec0c77e96b1bd69736b89665'


def test_bytes():
    assert md5( b'\x54\x68\x6f' ) == 'e3193c2f8542f80fb6633887d39827e8'
