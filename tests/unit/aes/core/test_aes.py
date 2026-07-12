from pytest import mark, raises

from purepython_aes.aes.core import AesCore


@mark.quick
class TestAesCore:
    @staticmethod
    def test_creation_fail() -> None:
        with raises(
            expected_exception=TypeError,
            match=' '.join(
                (
                    f'Can\'t instantiate abstract class {(AesCore.__name__)}',
                    'with abstract methods key_size, round_count',
                )
            ),
        ):
            AesCore(key=b'00112233445566778899aabbccddeeff')  # type: ignore[abstract]
