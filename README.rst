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

More info
=========

`Read full documentation <http://vk.readthedocs.org>`_
