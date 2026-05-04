import socket
import json

HOST = "127.0.0.1"
PORT = 9090


def send_request(sock: socket.socket, data: dict) -> dict:
    message = json.dumps(data, ensure_ascii=False) + "\n"
    sock.sendall(message.encode("utf-8"))
    response_raw = ""
    while True:
        chunk = sock.recv(4096).decode("utf-8")
        response_raw += chunk
        if "\n" in response_raw:
            line, _ = response_raw.split("\n", 1)
            return json.loads(line)


def print_separator() -> None:
    print("-" * 50)


def menu_check_user(sock: socket.socket) -> None:
    username = input("Введите имя пользователя: ").strip()
    resp = send_request(sock, {"command": "check_user", "username": username})
    print_separator()
    if resp.get("status") == "ok":
        print(f"Пользователь : {resp['username']}")
        print(f"Статус       : {resp['user_status']}")
        print(f"Роль         : {resp['role']}")
        print(f"Смена пароля : {resp['last_change_date']}")
    else:
        print(resp.get("message", "Ошибка"))
    print_separator()


def menu_log_access(sock: socket.socket) -> None:
    username = input("Имя пользователя  : ").strip()
    resource = input("Ресурс             : ").strip()
    action = input("Действие           : ").strip()
    resp = send_request(sock, {"command": "log_access", "username": username, "resource": resource, "action": action})
    print_separator()
    print(resp.get("message", resp))
    print_separator()


def menu_get_audit_log(sock: socket.socket) -> None:
    resp = send_request(sock, {"command": "get_audit_log"})
    print_separator()
    log = resp.get("log", [])
    if not log:
        print(resp.get("message", "Журнал пуст"))
    else:
        for entry in log:
            print(f"[{entry['timestamp']}] {entry['type']:20s} | {entry['details']}")
    print_separator()


def menu_check_password(sock: socket.socket) -> None:
    password = input("Введите пароль для проверки: ").strip()
    resp = send_request(sock, {"command": "check_password", "password": password})
    print_separator()
    print(resp.get("message", ""))
    violations = resp.get("violations", [])
    if violations:
        print("Нарушения политики:")
        for v in violations:
            print(f"  - {v}")
    print_separator()


def menu_register_incident(sock: socket.socket) -> None:
    description = input("Описание инцидента : ").strip()
    print("Уровень критичности: low / medium / high / critical")
    severity = input("Уровень            : ").strip()
    reported_by = input("Кто сообщил        : ").strip()
    resp = send_request(sock, {
        "command": "register_incident",
        "description": description,
        "severity": severity,
        "reported_by": reported_by,
    })
    print_separator()
    print(resp.get("message", resp))
    if "incident_id" in resp:
        print(f"Идентификатор инцидента : {resp['incident_id']}")
        print(f"Уровень критичности     : {resp['severity']}")
    print_separator()


MENU_ITEMS = {
    "1": ("Проверить статус пользователя", menu_check_user),
    "2": ("Зарегистрировать доступ к ресурсу", menu_log_access),
    "3": ("Просмотреть журнал аудита", menu_get_audit_log),
    "4": ("Проверить пароль на соответствие политике", menu_check_password),
    "5": ("Зарегистрировать инцидент ИБ", menu_register_incident),
    "0": ("Выход", None),
}


def print_menu() -> None:
    print("\n" + "=" * 50)
    print("  Система контроля доступа и мониторинга ИБ")
    print("=" * 50)
    for key, (label, _) in MENU_ITEMS.items():
        print(f"  {key}. {label}")
    print("=" * 50)


def main() -> None:
    print(f"Подключение к серверу {HOST}:{PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            print("Соединение установлено.\n")
            while True:
                print_menu()
                choice = input("Выберите пункт меню: ").strip()
                if choice not in MENU_ITEMS:
                    print("Неверный пункт меню. Попробуйте снова.")
                    continue
                label, handler = MENU_ITEMS[choice]
                if choice == "0":
                    send_request(sock, {"command": "bye"})
                    print("Соединение закрыто. До свидания!")
                    break
                print(f"\n--- {label} ---")
                try:
                    handler(sock)
                except Exception as exc:
                    print(f"Ошибка при выполнении операции: {exc}")
    except ConnectionRefusedError:
        print(f"Ошибка: не удалось подключиться к серверу {HOST}:{PORT}.")
        print("Убедитесь, что сервер запущен.")


if __name__ == "__main__":
    main()
