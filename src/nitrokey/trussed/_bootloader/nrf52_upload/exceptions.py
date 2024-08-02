from typing import Optional


class NordicSemiException(Exception):
    """
    Exception used as based exception for other exceptions defined in this package.
    """

    def __init__(self, msg: str, error_code: Optional[int] = None) -> None:
        super(NordicSemiException, self).__init__(msg)
        self.msg = msg
        self.error_code = error_code
