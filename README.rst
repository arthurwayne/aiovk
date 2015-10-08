=====================================
vk.com API Python wrapper for asyncio
=====================================

This is a vk.com (the largest Russian social network)
python API wrapper. The goal is to support all API methods (current and future)
that can be accessed from server and use asyncio. This is dirty fork of
`vk <https://github.com/dimka665/vk>`_

Quickstart
==========

Usage
-----

.. code:: python

    >>> import vk
    >>> session = vk.Session()
    >>> api = vk.API(session)
    >>> yield from api.users.get(user_ids=1)
    [{'first_name': 'Pavel', 'last_name': 'Durov', 'id': 1}]

See https://vk.com/dev/methods for detailed API guide.

Upload requires file-like objects with `name` field. If you `open` files and
pass file-like object it's ok. But, when you want store bytes, you need wrap
them with BytesIO and give a name to them, so aiohttp can determine what it is.

Simple example:

.. code:: python

    class NamedBytesIO(io.BytesIO):

        def __init__(self, name, *args, **kwargs):

            super().__init__(*args, **kwargs)
            self.name = name

    class VKSender:

        def __init__(self, *, app_id, login, password):

            session = aiovk.InteractiveAuthSession(
                app_id,
                login,
                password,
                "messages,photos"
            )
            self.vk = aiovk.API(session)

        @asyncio.coroutine
        def upload_photo_to_send(self, binary):

            response = yield from self.vk.photos.getMessagesUploadServer()
            url = response['upload_url']
            response = yield from self.vk.upload(url, photo=binary)
            response = yield from self.vk.photos.saveMessagesPhoto(**response)
            return response[0]["id"]

        @asyncio.coroutine
        def say_something(self, data):

            links = []
            for name, binary in data:

                file_like = NamedBytesIO(name, binary)
                links.append((yield from self.upload_photo_to_send(file_like)))

            yield from self.vk.messages.send(
                user_id="6666666",
                message="AAAAAAAA!",
                attachment=str.join(",", links)
            )


    if __name__ == "__main__":

        loop = asyncio.get_event_loop()
        vk = VKSender(
            app_id="00000000",
            login="user@mail.com",
            password="secret_password",
        )
        bins = []
        for name in ("naked_guido.jpg", "big-dick.png"):

            with open(name, "rb") as fin:

                bins.append((name, fin.read()))

        loop.run_until_complete(vk.yoba(bins))


More info
=========

`Read full documentation <http://vk.readthedocs.org>`_
