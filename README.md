lil-blog-uploader
=================

This program is used to upload image files for inclusion in the [LIL
blog](https://lil.law.harvard.edu/). It is deployed to a
[Dokku](https://dokku.com/) instance.

For development, [install
Poetry](https://python-poetry.org/docs/#installation) and run

    poetry install

in this directory to set up the environment. For deployment,
if there have been any changes to `poetry.lock`, export the
conventional requirements file like this:

    poetry export -o requirements.txt
