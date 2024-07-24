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
check: check-format check-import-sorting check-poetry check-style check-typing

.PHONY: check-format
check-format:
	poetry run black --check src stubs

.PHONY: check-import-sorting
check-import-sorting:
	poetry run isort --check-only src stubs

.PHONY: check-poetry
check-poetry:
	poetry check

.PHONY: check-style
check-style:
	poetry run flake8 src

.PHONY: check-typing
check-typing:
	poetry run mypy src

.PHONY: fix
fix:
	poetry run black src stubs
	poetry run isort src stubs

.PHONY: test
test:
	poetry run python -m unittest -v
