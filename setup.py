import setuptools

with open('README.md', 'r', encoding='utf-8') as readme_file:
    long_description = readme_file.read()

setuptools.setup(
    name='cryptidy',
    # packages = ['cryptidy'],
    packages=setuptools.find_packages(),
    version='1.0.4',
    license='BSD',
    description='Python high level library for symmetric & asymmetric encryption',
    author='Orsiris de Jong',
    author_email='ozy@netpower.fr',
    url='https://github.com/netinvent/cryptidy',
    keywords=['cryptography', 'symmetric', 'asymmetric', 'high', 'level', 'api', 'easy'],
    long_description=long_description,
    long_description_content_type='text/markdown',
    pyton_requires='>=3.3',
    install_requires=[
        'pycryptodomex',
    ],
    classifiers=[
        # command_runner is mature
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development",
        "Topic :: System",
        "Topic :: System :: Operating System",
        "Topic :: System :: Shells",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX :: BSD :: FreeBSD",
        "Operating System :: POSIX :: BSD :: NetBSD",
        "Operating System :: POSIX :: BSD :: OpenBSD",
        "Operating System :: Microsoft",
        "Operating System :: Microsoft :: Windows",
        "License :: OSI Approved :: BSD License",
    ],
)
