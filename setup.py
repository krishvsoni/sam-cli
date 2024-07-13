from setuptools import setup, find_packages

setup(
    name='sam-cli',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sam=sam.cli:main',
        ],
    },
    install_requires=[
        'antlr4-python3-runtime==4.7.2',
        'luaparser==3.2.1',
        'jinja2==2.11.3',
    ],
)
