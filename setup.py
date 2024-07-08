from setuptools import setup, find_packages

setup(
    name='sam',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sam=sam.cli:main',
        ],
    },
)
