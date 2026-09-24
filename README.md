# SkyNetwork FSD

Главный сервер сети виртуальной авиации **SkyNetwork** (Flight Simulator Daemon), написан на C++17. Он принимает координаты самолётов, передаёт данные между пользователями и координирует сеть. Работает по классическому текстовому **протоколу FSD**, который открыл Marty Bochane.

- TCP-порт `6809`: один поток, неблокирующий ввод-вывод через `poll()`
- Пакеты: `#AP`/`#AA` (вход), `@`/`%` (позиции), `#TM`, `$FP`, `$AM`, `$CQ`/`$CR`, `$PI`/`$PO`, `#DP`/`#DA`, `$ER`
- Авторизация по CID и паролю (PBKDF2-SHA256 в SQLite), рейтинги OBS…ADM, блокировка аккаунтов
- Позиции рассылаются только тем, кто в зоне видимости: у пилотов 60 nm, у диспетчеров — их радиус, но не больше 600 nm
- Флайт-планы: подача, запрос у сервера, правка диспетчером
- Сообщения: личные, на частоту (`@18100`), супервизорам (`*S`), общая рассылка (`*`, только SUP и ADM)
- Защита от подмены позывного, тайм-ауты, ограничения размера буферов
- JSON-фид онлайна: `http://host:8080/data.json`

Голосовой сервер сети — в отдельном репозитории **Skynetwork-voice**. Он использует ту же базу аккаунтов.

## Сборка и запуск

```bash
sudo apt install cmake g++ libssl-dev libsqlite3-dev
cmake -B build && cmake --build build -j
./build/skynet-admin --db skynetwork.db adduser 1000001 "Ivan Petrov" secret S2
./build/skynet-fsd --db skynetwork.db --port 6809 --http-port 8080
```

`skynet-admin` умеет: `adduser CID NAME PASSWORD [RATING]`, `rating CID RATING`, `passwd CID PASSWORD`, `suspend CID`, `unsuspend CID`.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```
