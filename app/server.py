import socket
import json
import threading
import re
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9090

USERS = {
    "ivanov": {"status": "active", "role": "analyst", "password_changed": "2025-03-10"},
    "petrov": {"status": "blocked", "role": "operator", "password_changed": "2024-11-01"},
    "sidorov": {"status": "active", "role": "admin", "password_changed": "2025-04-20"},
    "kozlov": {"status": "active", "role": "guest", "password_changed": "2024-09-15"},
}

RESOURCES = ["сервер БД", "файловый сервер", "почтовый сервер", "web-портал", "система мониторинга"]

AUDIT_LOG = []
LOCK = threading.Lock()


def log_event(event_type: str, details: str) -> None:
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "details": details,
    }
    with LOCK:
        AUDIT_LOG.append(entry)


def check_user(data: dict) -> dict:
    username = data.get("username", "").strip().lower()
    if not username:
        return {"status": "error", "message": "Не указано имя пользователя"}
    user = USERS.get(username)
    if user is None:
        log_event("CHECK_USER", f"Пользователь '{username}' не найден")
        return {"status": "not_found", "message": f"Пользователь '{username}' не найден в базе"}
    log_event("CHECK_USER", f"Проверка пользователя '{username}': {user['status']}")
    return {
        "status": "ok",
        "username": username,
        "user_status": user["status"],
        "role": user["role"],
        "last_change_date": user["password_changed"],
    }


def log_access(data: dict) -> dict:
    username = data.get("username", "").strip().lower()
    resource = data.get("resource", "").strip()
    action = data.get("action", "").strip()
    if not username or not resource or not action:
        return {"status": "error", "message": "Не указаны обязательные поля: username, resource, action"}
    user = USERS.get(username)
    if user is None:
        return {"status": "error", "message": f"Пользователь '{username}' не найден"}
    if user["status"] == "blocked":
        log_event("ACCESS_DENIED", f"Попытка доступа заблокированного пользователя '{username}' к '{resource}'")
        return {"status": "denied", "message": f"Доступ запрещён: пользователь '{username}' заблокирован"}
    log_event("ACCESS", f"Пользователь '{username}' выполнил '{action}' на ресурсе '{resource}'")
    return {"status": "ok", "message": f"Доступ зарегистрирован: '{username}' → '{action}' → '{resource}'"}


def get_audit_log(data: dict) -> dict:
    with LOCK:
        log_copy = list(AUDIT_LOG)
    if not log_copy:
        return {"status": "ok", "log": [], "message": "Журнал аудита пуст"}
    return {"status": "ok", "log": log_copy}


def check_password_policy(data: dict) -> dict:
    password = data.get("password", "")
    if not password:
        return {"status": "error", "message": "Не указан пароль для проверки"}
    violations = []
    if len(password) < 8:
        violations.append("длина менее 8 символов")
    if not re.search(r"[A-Z]", password):
        violations.append("отсутствует заглавная буква")
    if not re.search(r"[a-z]", password):
        violations.append("отсутствует строчная буква")
    if not re.search(r"\d", password):
        violations.append("отсутствует цифра")
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>?/\\|`~]", password):
        violations.append("отсутствует специальный символ")
    log_event("PASSWORD_CHECK", f"Проверка пароля: {'нарушения: ' + ', '.join(violations) if violations else 'пройдена'}")
    if violations:
        return {"status": "fail", "message": "Пароль не соответствует политике", "violations": violations}
    return {"status": "ok", "message": "Пароль соответствует политике безопасности"}


def register_incident(data: dict) -> dict:
    description = data.get("description", "").strip()
    severity = data.get("severity", "medium").strip().lower()
    reported_by = data.get("reported_by", "неизвестно").strip()
    if not description:
        return {"status": "error", "message": "Не указано описание инцидента"}
    valid_severities = {"low", "medium", "high", "critical"}
    if severity not in valid_severities:
        severity = "medium"
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    log_event(
        "INCIDENT",
        f"[{incident_id}] Уровень: {severity} | Сообщил: {reported_by} | Описание: {description}",
    )
    return {
        "status": "ok",
        "incident_id": incident_id,
        "message": f"Инцидент зарегистрирован с идентификатором {incident_id}",
        "severity": severity,
    }


HANDLERS = {
    "check_user": check_user,
    "log_access": log_access,
    "get_audit_log": get_audit_log,
    "check_password": check_password_policy,
    "register_incident": register_incident,
}


def handle_client(conn: socket.socket, addr: tuple) -> None:
    print(f"[+] Подключение от {addr}")
    with conn:
        buffer = ""
        while True:
            try:
                chunk = conn.recv(4096).decode("utf-8")
                if not chunk:
                    break
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        request = json.loads(line)
                    except json.JSONDecodeError:
                        response = {"status": "error", "message": "Неверный формат JSON"}
                        conn.sendall((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                        continue
                    command = request.get("command", "")
                    print(f"[{addr}] >>> команда: {json.dumps(request, ensure_ascii=False)}")
                    if command == "bye":
                        response = {"status": "ok", "message": "До свидания!"}
                        print(f"[{addr}] <<< ответ:  {json.dumps(response, ensure_ascii=False)}")
                        conn.sendall((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                        return
                    handler = HANDLERS.get(command)
                    if handler is None:
                        response = {"status": "error", "message": f"Неизвестная команда: '{command}'"}
                    else:
                        try:
                            response = handler(request)
                        except Exception as exc:
                            response = {"status": "error", "message": f"Внутренняя ошибка: {exc}"}
                    print(f"[{addr}] <<< ответ:  {json.dumps(response, ensure_ascii=False)}")
                    conn.sendall((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            except ConnectionResetError:
                break
    print(f"[-] Отключение {addr}")


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)
        print(f"Сервер запущен на {HOST}:{PORT}. Ожидание подключений...")
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
