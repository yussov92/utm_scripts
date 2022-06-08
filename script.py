"""
python3 script.py --utm_ip=1.1.1.1
                       --utm_login=administrator
                       --utm_password=servicemode
"""
import requests
import argparse
from api_schema.users import CREATE_USER_HANDLER, USER_IP_MAC_AUTH, users_schema
from api_schema.aliase import PORT_LIST, PORT_HANDLER, IP_HANDLER, DOMAIN_HANDLER, IP_LIST_HANDLER, aliase_schema
from api_schema.firewall import FORWARD_HANDLER, firewall_schema
from dataclasses import asdict

parser = argparse.ArgumentParser()

parser.add_argument('--utm_ip', help="IP адрес UTM-а")
parser.add_argument('--utm_login', help="Логин администратора")
parser.add_argument('--utm_password', help='Пароль администратора')

args = parser.parse_args()


def main():
    with requests.Session() as session:
        # авторизация на UTM
        session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443/web/auth/login",
            json={
                "login": args.utm_login,
                "password": args.utm_password,
                "recaptcha": ""
            },
            verify=False)
        ###########################################################################################
        ######################################  ОБЪЕКТЫ  ##########################################
        ###########################################################################################

        # создание пользователя
        test_user = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{CREATE_USER_HANDLER}",
            json=asdict(users_schema['create_user'](
                parent_id=1,
                name='test_user_name',
                login='test_user_login',
                psw='TeStUsErPaSsWoRd123456'
            )),
            verify=False
        ).json()

        # назначение IP адреса на пользователя
        session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{USER_IP_MAC_AUTH}",
            json=asdict(users_schema['user_ip_mac_auth'](
                always_logged=True,
                comment='test_ip_auth',
                enabled=True,
                ip='192.168.168.168',
                mac=None,
                user_id=test_user['id']
            )),
            verify=False
        )

        user_obj = f"user.id.{test_user['id']}"

        # создание объекта "Домен ya.ru"
        domain_ya_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{DOMAIN_HANDLER}",
            json=asdict(aliase_schema['aliase'](
                title='ya_domain_object',
                comment='ya_domain_object',
                value='ya.ru'
            )),
            verify=False
        ).json()

        # создание объекта "Домен netflix.com"
        domain_netflix_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{DOMAIN_HANDLER}",
            json=asdict(aliase_schema['aliase'](
                title='netflix_domain_object',
                comment='netflix_domain_object',
                value='netflix.com'
            )),
            verify=False
        ).json()

        # создание объекта "IP-адрес"
        ip_address_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{IP_HANDLER}",
            json=asdict(aliase_schema['aliase'](
                title='ip_address_object',
                comment='ip_address_object',
                value='34.23.123.54'
            )),
            verify=False
        ).json()

        # создание объекта "Порт 777"
        port_777_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{PORT_HANDLER}",
            json=asdict(aliase_schema['aliase'](
                title='port 777',
                comment='port 777',
                value=777
            )),
            verify=False
        ).json()

        # создание объекта "Порт 888"
        port_888_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{PORT_HANDLER}",
            json=asdict(aliase_schema['aliase'](
                title='port 888',
                comment='port 888',
                value=888
            )),
            verify=False
        ).json()

        # создание объекта "Список адресов"
        address_list_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{IP_LIST_HANDLER}",
            json=asdict(aliase_schema['aliase_list'](
                title='addresses_list_object',
                comment='addresses_list_object',
                values=[domain_ya_obj['id'], ip_address_obj['id'], user_obj]
            )),
            verify=False
        ).json()

        # создание объекта "Порты"
        port_list_obj = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{PORT_LIST}",
            json=asdict(aliase_schema['aliase_list'](
                title='test_port',
                comment='test_port',
                values=[port_777_obj['id']]
            )),
            verify=False
        ).json()

        # добавление домена в обьект "Список адресов"
        session.request(
            method='PUT',
            url=f"https://{args.utm_ip}:8443{IP_LIST_HANDLER}/{address_list_obj['id']}",
            json=asdict(aliase_schema['aliase_list'](
                title='addresses_list',
                comment='addresses_list',
                values=[domain_ya_obj['id'], domain_netflix_obj['id'], user_obj]
            )),
            verify=False
        )

        # добавление порта в обьект "Порты"
        session.request(
            method='PUT',
            url=f"https://{args.utm_ip}:8443{PORT_LIST}/{port_list_obj['id']}",
            json=asdict(aliase_schema['aliase_list'](
                title='port_list',
                comment='port_list',
                values=[port_777_obj['id'], port_888_obj['id']]
            )),
            verify=False
        )

        # удаление домена из объекта "Список адресов"
        session.request(
            method='PUT',
            url=f"https://{args.utm_ip}:8443{IP_LIST_HANDLER}/{address_list_obj['id']}",
            json=asdict(aliase_schema['aliase_list'](
                title='addresses_list',
                comment='addresses_list',
                values=[domain_netflix_obj['id'], user_obj]
            )),
            verify=False
        )

        # удаление порта из обьекта "Порты"
        session.request(
            method='PUT',
            url=f"https://{args.utm_ip}:8443{PORT_LIST}/{port_list_obj['id']}",
            json=asdict(aliase_schema['aliase_list'](
                title='port_list',
                comment='port_list',
                values=[port_888_obj['id']]
            )),
            verify=False
        )

        ###########################################################################################
        ######################################  ФАЙРВОЛ  ##########################################
        ###########################################################################################

        # создание правила файрвола в цепочке FORWARD
        # заблокировать доступ до IP 34.23.123.54 на порт 777 для пользователя test_user_name
        forward_1_rule = session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{FORWARD_HANDLER}",
            json=asdict(firewall_schema['firewall_forward'](
                action='drop',
                comment='firewall_1_rule',
                destination_addresses=[ip_address_obj['id']],
                destination_ports=[port_777_obj['id']],
                incoming_interface='any',
                outgoing_interface='any',
                protocol='protocol.tcp',
                source_addresses=[f'user.id.{test_user["id"]}'],
                timetable=['any'],
                enabled=True
            )),
            verify=False
        ).json()
        print(forward_1_rule)

        # заблокировать доступ до netflix.com для всех пользователей
        session.request(
            method='POST',
            url=f"https://{args.utm_ip}:8443{FORWARD_HANDLER}",
            json=asdict(firewall_schema['firewall_forward'](
                action='drop',
                comment='firewall_2_rule',
                destination_addresses=[domain_netflix_obj['id']],
                destination_ports=['any'],
                incoming_interface='any',
                outgoing_interface='any',
                protocol='any',
                source_addresses=['any'],
                timetable=['any'],
                enabled=True
            )),
            verify=False
        )

        # удалить правило файрвола forward_1_rule
        session.request(
            method='DELETE',
            url=f"https://{args.utm_ip}:8443{FORWARD_HANDLER}/{forward_1_rule['id']}",
            verify=False
        )


if __name__ == '__main__':
    main()
