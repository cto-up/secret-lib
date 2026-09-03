include .env
export $(shell sed 's/=.*//' .env)
DB_CONNECTION = postgres://${DATABASE_USERNAME}:${DATABASE_PASSWORD}@${DATABASE_URL}
COMMAND ?= new # new:front_views
FILE ?= entity.json

testme:
	env

postgresup:
	docker compose -f docker/postgresql.yml up

postgresdown:
	docker compose -f docker/postgresql.yml down

sqlc:
	cd pkg/db; echo "I'm in backend secret"; \
	sqlc generate


BASE_API_BE_DIR := api/openapi
# The frontend client is generated into the copy you can TEST — hub's
# submodule — not the sibling clone no consumer builds. Overridable for a
# checkout somewhere else. Only lib/ is wiped; everything beside it is
# hand-authored.
FE_LIB_NAME := secret-fe-lib
BASE_FE_DIR ?= ../hub/frontend/$(FE_LIB_NAME)
BASE_API_FE_DIR := $(BASE_FE_DIR)/lib

# Define the pattern to search for and replace
SEARCH_STRING_1 := from \'./core
REPLACE_STRING_1 := from \'core-fe-lib/openapi/core/core

SEARCH_STRING_2 := from \'../core
REPLACE_STRING_2 := from \'core-fe-lib/openapi/core/core

BASE_OPENAPI_DIR := pkg/api/openapi

build:
	go build ./...

test:
	go test -v -race ./...

openapi: check-fe-checkout
	@echo "Generating OpenAPI code"
	@rm -rf $(BASE_API_FE_DIR)
	openapi --input $(BASE_OPENAPI_DIR)/secret-api.yaml --output $(BASE_API_FE_DIR) --client axios
	@rm -rf $(BASE_API_FE_DIR)/core
	@find $(BASE_API_FE_DIR) -name "*.ts" -type f -exec sed -i '' "s|$(SEARCH_STRING_1)|$(REPLACE_STRING_1)|g" {} +
	@find $(BASE_API_FE_DIR) -name "*.ts" -type f -exec sed -i '' "s|$(SEARCH_STRING_2)|$(REPLACE_STRING_2)|g" {} +
	@echo "Replacement complete."

	oapi-codegen -config $(BASE_OPENAPI_DIR)/_oapi-schema-config.yaml $(BASE_OPENAPI_DIR)/secret-schema.yaml > api/openapi/secret-schema.go
	oapi-codegen -config $(BASE_OPENAPI_DIR)/_oapi-service-config.yaml $(BASE_OPENAPI_DIR)/secret-api.yaml > api/openapi/secret-service.go

update-core-backend:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION parameter is required. Use 'vx.x.x' format."; \
		exit 1; \
	fi
	go get -u ctoup.com/coreapp@$(VERSION)


release:
	@echo "Creating release"
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION parameter is required. Use 'vx.x.x' format."; \
		exit 1; \
	fi; \
	gh release create $(VERSION) --title "$(VERSION)" --notes "$(NOTES)"

include .env
export $(shell sed 's/=.*//' .env)
DB_CONNECTION = postgres://${DATABASE_USERNAME}:${DATABASE_PASSWORD}@${DATABASE_URL}


.PHONY: check-fe-checkout postgresup postgresdown sqlc test openapi build update-core-backend test

# The generator writes into a git checkout that must be able to PUSH what it
# produces. A submodule is detached by default, and a client generated onto a
# detached HEAD is a client nobody else can ever receive.
check-fe-checkout:
	@test -e $(BASE_FE_DIR)/.git || { \
		echo "ERROR: $(BASE_FE_DIR) is not a checkout."; \
		echo "       Run: git -C ../hub submodule update --init frontend/$(FE_LIB_NAME)"; \
		exit 1; }
	@cd $(BASE_FE_DIR) && git fetch -q origin 2>/dev/null || true
	@cd $(BASE_FE_DIR) && \
		branch=$$(git symbolic-ref --quiet --short HEAD || echo DETACHED); \
		if [ "$$branch" = "DETACHED" ]; then \
			echo "ERROR: $(BASE_FE_DIR) is on a detached HEAD, so what you generate cannot be pushed."; \
			echo "       Run: make -C ../hub libs-attach"; \
			exit 1; \
		fi; \
		behind=$$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0); \
		if [ "$$behind" != "0" ]; then \
			echo "ERROR: $(BASE_FE_DIR) is $$behind commit(s) behind origin/main."; \
			echo "       Generating here would build a client against stale source."; \
			echo "       Run: cd $(BASE_FE_DIR) && git pull --ff-only"; \
			exit 1; \
		fi
