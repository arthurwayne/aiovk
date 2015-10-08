
import sys


LOGGING_CONFIG = {
    'version': 1,
    'loggers': {
        'vk': {
            'level': 'ERROR',
            'handlers': ['vk-stdout'],
            'propagate': False,
            },
        },
    'handlers': {
        'vk-stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'vk-verbose',
        },
    },
    'formatters': {
        'vk-verbose': {
            'format': '%(asctime)s %(name) -5s %(module)s:%(lineno)d %(levelname)s: %(message)s',
        },
    },
}
