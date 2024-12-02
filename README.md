<h2>Описание</h2>
Этот проект представляет собой сервис аутентификации с использованием JWT и базы данных PostgreSQL. Он предоставляет API для генерации и обновления токенов доступа (access) и обновления (refresh).

<h2> Функционал </h2>

- Генерация пары Access и Refresh токенов для пользователя.
- Обновление токенов с проверкой связности и валидацией IP-адреса.
- Предупреждение при изменении IP-адреса пользователя.

<h2> Стек </h2>

- Go
- PostgreSQL
- JWT (SHA-512), bcrypt
- Gin 
