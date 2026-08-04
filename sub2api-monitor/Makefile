.PHONY: config build up down logs test frontend-test backend-test

config:
	docker compose config --quiet

build:
	docker compose build

up:
	docker compose up -d --wait

down:
	docker compose down

logs:
	docker compose logs -f api worker web

frontend-test:
	cd frontend && npm test

backend-test:
	cd backend && pytest

test: backend-test frontend-test
