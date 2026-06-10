import pytest
from hashlib import sha256, sha512
from typing import Callable, Optional, Tuple
import builtins

builtins.Callable = Callable
builtins.Optional = Optional
builtins.Tuple = Tuple

from student_feistel import Feistel as StudentFeistel
from reference_feistel import Feistel as RefFeistel

def SHA256(message: bytes) -> bytes:
    alg = sha256()
    alg.update(message)
    return alg.digest()

def SHA512(message: bytes) -> bytes:
    alg = sha512()
    alg.update(message)
    return alg.digest()

configs = [
    (64, 10, SHA256, b'secret_key_256', 'SHA256'),
    (128, 15, SHA512, b'secret_key_512', 'SHA512')
]

@pytest.fixture(params=configs, ids=[c[4] for c in configs])
def nets(request):
    block_length, number_rounds, hash_function, secret_key, _ = request.param
    student_net = StudentFeistel(block_length, number_rounds, hash_function, secret_key)
    ref_net = RefFeistel(block_length, number_rounds, hash_function, secret_key)
    return student_net, ref_net

msg_ok_factors = [
    lambda l: b'A' * l,
    lambda l: b'\x00\xff' * (l//2),
    lambda l: b'12345678' * (l//8)
]

msg_fail_factors = [
    lambda l: b'A' * (l - 1),
    lambda l: b'B' * (l + 1),
    lambda l: b'\x00' * (l - 3)
]

pad_not_div_factors = [
    lambda l: b'A' * (l - 5),
    lambda l: b'Z',
    lambda l: b'\x12' * (l + 5)
]

ecb_cbc_ok_factors = msg_ok_factors + [
    lambda l: b'A' * (l * 2),
    lambda l: b'\x00\xff' * ((l * 3)//2)
]

ecb_cbc_not_div_factors = pad_not_div_factors + [
    lambda l: b'A' * (l * 2 - 5),
    lambda l: b'\x12' * (l * 3 + 5)
]

# 1. enc_block ok
@pytest.mark.parametrize("msg_factory", msg_ok_factors)
def test_enc_block_ok(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    assert student_net.enc_block(msg) == ref_net.enc_block(msg)

# 2. enc_block fail
@pytest.mark.parametrize("msg_factory", msg_fail_factors)
def test_enc_block_fail(nets, msg_factory):
    student_net, _ = nets
    msg = msg_factory(student_net.block_length)
    with pytest.raises(Exception):
        student_net.enc_block(msg)

# 3. dec_block ok
@pytest.mark.parametrize("msg_factory", msg_ok_factors)
def test_dec_block_ok(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    ref_c = ref_net.enc_block(msg)
    assert student_net.dec_block(ref_c) == msg

# 4. dec_block fail
@pytest.mark.parametrize("msg_factory", msg_fail_factors)
def test_dec_block_fail(nets, msg_factory):
    student_net, _ = nets
    msg = msg_factory(student_net.block_length)
    with pytest.raises(Exception):
        student_net.dec_block(msg)

# 5. key_schedule
@pytest.mark.parametrize("round_idx", [1, 5, 10])
def test_key_schedule(nets, round_idx):
    student_net, ref_net = nets
    assert student_net.key_schedule(round_idx) == ref_net.key_schedule(round_idx)

# 6. pad len not div
@pytest.mark.parametrize("msg_factory", pad_not_div_factors)
def test_pad_not_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    assert student_net.pad(msg) == ref_net.pad(msg)

# 7. pad len div
@pytest.mark.parametrize("msg_factory", msg_ok_factors)
def test_pad_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    assert student_net.pad(msg) == ref_net.pad(msg)

# 8. unpad correct
@pytest.mark.parametrize("msg_factory", pad_not_div_factors + msg_ok_factors)
def test_unpad_correct(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    padded = ref_net.pad(msg)
    assert student_net.unpad(padded) == msg

# 9. unpad fail length
@pytest.mark.parametrize("msg_factory", pad_not_div_factors)
def test_unpad_fail_length(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    bad_padded = ref_net.pad(msg)[:-1] 
    with pytest.raises(Exception):
        student_net.unpad(bad_padded)

# 10. unpad fail rules
@pytest.mark.parametrize("msg_factory", pad_not_div_factors)
def test_unpad_fail_rules(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    bad_padded = ref_net.pad(msg)[:-1] + b'2'
    with pytest.raises(Exception):
        student_net.unpad(bad_padded)

# 11. enc ECB div
@pytest.mark.parametrize("msg_factory", ecb_cbc_ok_factors)
def test_enc_ecb_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    assert student_net.enc(msg, 'ECB') == ref_net.enc(msg, 'ECB')

# 12. enc ECB not div
@pytest.mark.parametrize("msg_factory", ecb_cbc_not_div_factors)
def test_enc_ecb_not_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    assert student_net.enc(msg, 'ECB') == ref_net.enc(msg, 'ECB')

# 13. dec ECB div
@pytest.mark.parametrize("msg_factory", ecb_cbc_ok_factors)
def test_dec_ecb_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    ref_c = ref_net.enc(msg, 'ECB')
    assert student_net.dec(ref_c, 'ECB') == msg

# 14. dec ECB not div
@pytest.mark.parametrize("msg_factory", ecb_cbc_not_div_factors)
def test_dec_ecb_not_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    ref_c = ref_net.enc(msg, 'ECB')[:-1] 
    with pytest.raises(Exception):
        student_net.dec(ref_c, 'ECB')

# 15. CBC div
@pytest.mark.parametrize("msg_factory", ecb_cbc_ok_factors)
def test_cbc_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    student_c, iv = student_net.enc(msg, 'CBC')
    ref_c, _ = ref_net.enc(msg, 'CBC', IV=iv)
    print(student_net.block_length)
    print(msg)
    print(student_c)
    print(ref_c)
    assert student_c == ref_c
    assert student_net.dec(student_c, 'CBC', IV=iv) == msg

# 16. CBC not div
@pytest.mark.parametrize("msg_factory", ecb_cbc_not_div_factors)
def test_cbc_not_div(nets, msg_factory):
    student_net, ref_net = nets
    msg = msg_factory(student_net.block_length)
    student_c, iv = student_net.enc(msg, 'CBC')
    ref_c, _ = ref_net.enc(msg, 'CBC', IV=iv)
    assert student_c == ref_c
    assert student_net.dec(student_c, 'CBC', IV=iv) == msg
