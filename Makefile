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
BASE_API_FE_DIR := ../secret-fe-lib

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

openapi:
	@echo "Generating OpenAPI code"
	@find $(BASE_API_FE_DIR) -type f -name "*.ts" -delete
	openapi --input $(BASE_OPENAPI_DIR)/secret-api.yaml --output $(BASE_API_FE_DIR) --client axios
	@rm -rf $(BASE_API_FE_DIR)/$(MODULE)/core
	@find $(BASE_API_FE_DIR)/$(MODULE) -name "*.ts" -type f -exec sed -i '' "s|$(SEARCH_STRING_1)|$(REPLACE_STRING_1)|g" {} +
	@find $(BASE_API_FE_DIR)/$(MODULE) -name "*.ts" -type f -exec sed -i '' "s|$(SEARCH_STRING_2)|$(REPLACE_STRING_2)|g" {} +
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


.PHONY: postgresup postgresdown sqlc test openapi build update-core-backend test
