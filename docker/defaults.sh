export BASE_URL=${BASE_URL:-"http://localhost:8080"}
export LISTENING_ADDR=${LISTENING_ADDR:-"0.0.0.0:8080"}
export DATABASE_NAMESPACE=${DATABASE_NAMESPACE:-"database"}
export ETCD_PREFIX=${ETCD_PREFIX:-"cylonix_manager"}
export REDIS_PREFIX=${REDIS_PREFIX:-"cylonix_redis"}
export PG_DB_NAME=${PG_DB_NAME:-"cylonix_manager"}
export SERVICE_SCHEME=${SERVICE_SCHEME:-"http"}

# Service names
export ETCD_SERVICE_NAME=${ETCD_SERVICE_NAME:-"etcd-service"}
export INFLUXDB_SERVICE_NAME=${INFLUXDB_SERVICE_NAME:-"influxdb-service"}
export IPDRAWER_SERVICE_NAME=${IPDRAWER_SERVICE_NAME:-"ip-drawer-service"}
export PROMETHEUS_SERVICE_NAME=${PROMETHEUS_SERVICE_NAME:-"prometheus-service"}
export POSTGRES_SERVICE_NAME=${POSTGRES_SERVICE_NAME:-"postgres-service"}
export REDIS_SERVICE_NAME=${REDIS_SERVICE_NAME:-"redis-service"}

# Ports
export ETCD_PORT=${ETCD_PORT:-2379}
export IPDRAWER_PORT=${IPDRAWER_PORT:-25577}
export PG_PORT=${PG_PORT:-5432}
export REDIS_PORT=${REDIS_PORT:-6379}
export PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}

# Task interval
export TASK_INTERVAL=${TASK_INTERVAL:-60}

# Headscale
export HEADSCALE_BASE_DOMAIN=${HEADSCALE_BASE_DOMAIN:-"example.com"}
