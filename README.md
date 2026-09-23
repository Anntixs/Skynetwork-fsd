# SkyNetwork

Сеть виртуальной авиации по типу VATSIM. Этот репозиторий содержит сервер сети — к нему подключаются пилотские и диспетчерские клиенты (их аналоги vPilot / xPilot / EuroScope появятся позже).

## Возможности

- TCP-сервер (порт `6809`), протокол — JSON-строки (см. `skynetwork/protocol.py`)
- Учётные записи участников (CID + пароль, PBKDF2), рейтинги `OBS…ADM`, блокировка
- Роли: пилот и диспетчер (диспетчер — от рейтинга `S1`)
- Позиции с фильтрацией по дальности видимости, флайт-планы, личные и частотные сообщения, рассылки супервизора
- Публичный JSON-фид онлайна: `http://host:8080/data.json` (для карт и статистики)
- Без внешних зависимостей, Python 3.11+

## Запуск

```bash
python -m skynetwork adduser 1000001 "Ivan Petrov" secret --rating S2
python -m skynetwork serve --port 6809 --http-port 8080
```

Управление: `rating CID S3`, `suspend CID`, `unsuspend CID`.

## Пример клиента

```python
from skynetwork.client import SkyNetworkClient
c = SkyNetworkClient()
await c.connect("localhost", 6809, 1000001, "secret", "AFL123")
await c.send("position", lat=55.97, lon=37.41, alt=3000, gs=180, hdg=250)
```

## Тесты

```bash
python -m unittest discover -s tests
```
