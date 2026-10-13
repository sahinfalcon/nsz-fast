from pathlib import Path
import importlib.util


def load_version_constants():
    version_path = (
        Path(__file__).resolve().parent.joinpath("nsz").joinpath("version.py")
    )
    spec = importlib.util.spec_from_file_location("nsz_version", str(version_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load nsz/version.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VERSION, module.GUI_VERSION


VERSION, GUI_VERSION = load_version_constants()


def read_long_description():
    readme_path = Path(__file__).resolve().parent.joinpath("README.md")
    with open(str(readme_path), "r", encoding="utf-8") as fh:
        return fh.read()


def get_setup_kwargs():
    return {
        "name": "nsz",
        "version": VERSION,
        "script": "nsz.py",
        "author": "Nico Bosshard",
        "author_email": "nico@bosshome.ch",
        "maintainer": "Nico Bosshard",
        "maintainer_email": "nico@bosshome.ch",
        "description": "NSZ - Homebrew compatible NSP/XCI compressor/decompressor",
        "long_description": read_long_description(),
        "long_description_content_type": "text/markdown",
        "url": "https://github.com/nicoboss/nsz",
        "packages": [
            "nsz",
            "nsz.Fs",
            "nsz.nut",
            "nsz.gui",
            "nsz.gui.txt",
            "nsz.gui.shaders",
            "nsz.gui.layout",
            "nsz.gui.json",
            "nsz.gui.fonts",
        ],
        "classifiers": [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        "install_requires": [
            "pycryptodome",
            "cryptography",
            "zstandard",
            "enlighten",
        ],
        "extras_require": {
            "gui": [
                'pywin32;platform_system=="Windows"',
                'pypiwin32;platform_system=="Windows"',
                "kivy",
            ],
        },
        "entry_points": {"console_scripts": ["nsz = nsz:main"]},
        "keywords": ["nsz", "xcz", "ncz", "nsp", "xci", "nca", "Switch"],
        "python_requires": ">=3.6",
        "zip_safe": False,
        "include_package_data": True,
    }


def main():
    import setuptools

    setuptools.setup(**get_setup_kwargs())


if __name__ == "__main__":
    main()
