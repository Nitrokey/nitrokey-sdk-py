import random
import string
import unittest
from dataclasses import asdict
from typing import List, Tuple

from nitrokey.nk3.credential_exchange_format import (
    BasicAuth,
    Item,
    NitrokeyPasswordExtension,
    PasswordToCXF,
)
from nitrokey.nk3.secrets_app import (
    Algorithm,
    Kind,
    ListItem,
    ListItemProperties,
    PasswordSafeEntry,
)


def test_equality(item: Item, list_item: ListItem, pse: PasswordSafeEntry) -> None:
    assert item.title.encode() == list_item.label
    assert item.credentials and item.credentials[0]
    assert isinstance(item.credentials[0], BasicAuth)
    assert item.extensions and item.extensions[0]
    assert isinstance(item.extensions[0], NitrokeyPasswordExtension)

    cred = item.credentials[0]
    ext = item.extensions[0]

    assert cred.username.value.encode() == pse.login
    assert cred.password.value.encode() == pse.password
    assert ext.metadata.encode() == pse.metadata
    assert isinstance(ext.item.properties, ListItemProperties)

    prop = ext.item.properties
    assert prop.touch_required == list_item.properties.touch_required
    assert prop.secret_encryption == list_item.properties.secret_encryption
    assert prop.pws_data_exist == list_item.properties.pws_data_exist


def test_list_equality(
    item_list: List[Item], list_item_list: List[ListItem], pse_list: List[PasswordSafeEntry]
) -> None:
    assert len(item_list) == len(list_item_list)
    assert len(item_list) == len(pse_list)
    for i in range(len(item_list)):
        test_equality(item_list[i], list_item_list[i], pse_list[i])
        # print("Success")


def generate_test_cases(n: int = 3) -> Tuple[List[ListItem], List[PasswordSafeEntry]]:
    list_item_list = []
    pse_list = []
    length = 10
    for _ in range(n):
        label = "".join(random.choice(string.ascii_letters) for _ in range(length))
        username = "".join(random.choice(string.ascii_letters) for _ in range(length))
        password = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(length)
        )
        prop = random.randrange(0, 8)
        metadata = "".join(random.choice(string.ascii_letters) for _ in range(length))

        list_item = ListItem(
            kind=Kind.NotSet,
            algorithm=Algorithm.Sha1,
            label=label.encode(),
            properties=ListItemProperties.from_byte(prop),
        )

        pse = PasswordSafeEntry(
            login=username.encode(), password=password.encode(), metadata=metadata.encode()
        )

        list_item_list.append(list_item)
        pse_list.append(pse)

    return list_item_list, pse_list


def list_convert_pse_to_item(
    list_item_list: List[ListItem], pse_list: List[PasswordSafeEntry]
) -> List[Item]:
    assert len(pse_list) == len(list_item_list)
    item_list = []
    for i in range(len(list_item_list)):
        item_list.append(PasswordToCXF.password_to_item(list_item_list[i], pse_list[i]))
    return item_list


def list_convert_item_to_pse(
    item_list: List[Item],
) -> Tuple[List[ListItem], List[PasswordSafeEntry]]:
    list_item_list = []
    pse_list = []
    for item in item_list:
        list_item, pse = PasswordToCXF.item_to_password(item)
        if not list_item or not pse:
            continue
        list_item_list.append(list_item)
        pse_list.append(pse)
    return list_item_list, pse_list


class TestPasswordExport(unittest.TestCase):
    def test_conversions(self) -> None:
        N = 10  # Number of tests

        # Will perform ListItem, PSE lists 1 --> Item List 1 --> CXF Payload 1 --> CXF Payload Dict --> CXF Payload 2 --> Item List 2 --> ListItem, PSE lists 2
        # Will check the following equalities:
        #   ListItem, PSE lists 1 <--> Item List 1
        #   ListItem, PSE lists 1 <--> Item List 2
        #   ListItem, PSE lists 2 <--> Item List 1
        #   ListItem, PSE lists 2 <--> Item List 2

        list_item_list_1, pse_list_1 = generate_test_cases(N)
        item_list_1 = list_convert_pse_to_item(list_item_list_1, pse_list_1)
        cxf_payload_1 = PasswordToCXF.items_to_cxf(item_list_1)
        cxf_payload_dict = asdict(cxf_payload_1)
        cxf_payload_2 = PasswordToCXF.cxf_from_dict(cxf_payload_dict)
        item_list_2 = PasswordToCXF.cxf_to_items(cxf_payload_2)
        list_item_list_2, pse_list_2 = list_convert_item_to_pse(item_list_2)

        test_list_equality(item_list_1, list_item_list_1, pse_list_1)
        test_list_equality(item_list_2, list_item_list_1, pse_list_1)
        test_list_equality(item_list_1, list_item_list_2, pse_list_2)
        test_list_equality(item_list_2, list_item_list_2, pse_list_2)


if __name__ == "__main__":
    TestPasswordExport().test_conversions()
