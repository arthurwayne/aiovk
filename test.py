import asyncio
import aiovk
import logging


@asyncio.coroutine
def yoba():

    session = aiovk.Session()
    api = aiovk.API(session)
    r = yield from api.users.get(user_ids=1)
    print(r)


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(message)s",
        datefmt="[%H:%M:%S]:",
    )
    asyncio.get_event_loop().run_until_complete(yoba())
