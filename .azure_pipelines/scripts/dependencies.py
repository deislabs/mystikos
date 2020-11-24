"""install dependencies

install all listed dependencies with specified versions.
"""

import apt
from utils import config
from config import DEPENDENCIES


class DependencyInstallError(RuntimeError):
    pass


def install_web_dependency():
    pass


def install_apt_dependency(cache: apt.cache.Cache,
                           pkg_name: str,
                           version: str = None):
    print(
        f"checking package {pkg_name} with version {version if version else 'Latest'}"
    )
    package = cache.get(pkg_name)
    if not package:
        raise DependencyInstallError(
            f"The dependency package {pkg_name} cannot be found.")

    version_match = version == package.candidate.version

    # exact package w/ exact version has already been installed
    if package.is_installed and version_match:
        print(
            f"package {pkg_name} with version {version} has already been installed, will skip."
        )
        return

    if version and not version_match:
        candidate = package.versions.get(version)
        if not candidate:
            raise DependencyInstallError(
                f"The specified version: {version} for package {pkg_name} canont be found"
            )
        package.candidate = candidate

    package.mark_install()


def main():
    with apt.cache.Cache() as cache:
        cache.update()
        for pkg, vers in DEPENDENCIES.items():
            install_apt_dependency(cache, pkg, vers)
        cache.commit()


if __name__ == "__main__":
    main()