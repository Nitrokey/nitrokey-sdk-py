FORMAT_DIRS := src stubs tests
LINT_DIRS := src tests

.PHONY: install
install:
	poetry install --sync --with dev

.PHONY: lock
lock:
	poetry lock --no-update

.PHONY: update
update:
	poetry update --with dev

.PHONY: check
check: check-format check-import-sorting check-poetry check-style check-typing check-docs

.PHONY: check-format
check-format:
	poetry run black --check $(FORMAT_DIRS)

.PHONY: check-import-sorting
check-import-sorting:
	poetry run isort --check-only $(FORMAT_DIRS)

.PHONY: check-poetry
check-poetry:
	poetry check

.PHONY: check-style
check-style:
	poetry run flake8 $(LINT_DIRS)

.PHONY: check-typing
check-typing:
	poetry run mypy $(LINT_DIRS)

.PHONY: check-docs
check-docs:
	poetry run rstcheck --recursive docs

.PHONY: fix
fix:
	poetry run black $(FORMAT_DIRS)
	poetry run isort $(FORMAT_DIRS)

.PHONY: test
test:
	poetry run python -m unittest -v

.PHONY: generate-protobuf
generate-protobuf:
	protoc src/nitrokey/trussed/_bootloader/nrf52_upload/dfu/dfu-cc.proto --python_out=. --pyi_out=.

.PHONY: generate-api-docs
generate-api-docs:
	poetry run sphinx-apidoc --separate --maxdepth 1 --tocfile index --output-dir docs/api src/nitrokey

.PHONY: build-docs
build-docs:
	poetry run sphinx-build --fail-on-warning docs _build

.PHONY: update-version
update-version: RPM_VERSION=$(shell poetry version --short | sed 's/-rc\./~rc/')
update-version:
	sed -i "/^Version:/s/[[:digit:]].*/$(RPM_VERSION)/" ci-scripts/linux/rpm/python3-nitrokey.spec
