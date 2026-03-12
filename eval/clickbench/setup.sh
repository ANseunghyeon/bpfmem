#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BIN_DIR="$DIR/bin"
DATA_DIR="/mnt/nvme/clickbench_data"
CONFIG_FILE="$DIR/config.xml"
USERS_FILE="$DIR/users.xml"

mkdir -p "$BIN_DIR"
mkdir -p "$DATA_DIR"

# Download clickhouse
if [ ! -f "$BIN_DIR/clickhouse" ]; then
    echo "Downloading ClickHouse..."
    # Using the official install script but directing output
    curl https://clickhouse.com/ | sh
    mv clickhouse "$BIN_DIR/"
    chmod +x "$BIN_DIR/clickhouse"
fi

# Download queries.sql
echo "Downloading queries.sql..."
curl -o "$DIR/queries.raw.sql" https://raw.githubusercontent.com/ClickHouse/ClickBench/main/versions/scripts/ch_queries.sql

# Process queries.sql to match our table schema
# Replace {table} with hits
# Replace Refresh with IsRefresh (as our table uses IsRefresh)
sed -e 's/{table}/hits/g' -e 's/Refresh/IsRefresh/g' "$DIR/queries.raw.sql" > "$DIR/queries.sql"


# Download hits.parquet
if [ ! -f "$DATA_DIR/hits.parquet" ]; then
    echo "Downloading hits.parquet..."
    curl -o "$DATA_DIR/hits.parquet" "https://datasets.clickhouse.com/hits_compatible/hits.parquet"
fi

# Create users.xml
cat > "$USERS_FILE" <<EOF
<clickhouse>
    <profiles>
        <default>
        </default>
    </profiles>
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>
    <quotas>
        <default>
        </default>
    </quotas>
</clickhouse>
EOF

# Create config.xml
cat > "$CONFIG_FILE" <<EOF
<clickhouse>
    <logger>
        <level>trace</level>
        <log>$DATA_DIR/clickhouse-server.log</log>
        <errorlog>$DATA_DIR/clickhouse-server.err.log</errorlog>
        <size>1000M</size>
        <count>10</count>
    </logger>
    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    <path>$DATA_DIR/</path>
    <tmp_path>$DATA_DIR/tmp/</tmp_path>
    <user_files_path>$DATA_DIR/user_files/</user_files_path>
    <users_config>$USERS_FILE</users_config>
    <default_profile>default</default_profile>
    <default_database>default</default_database>
    <timezone>UTC</timezone>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
EOF

# Start server to load data
echo "Starting ClickHouse server to load data..."
# We run it in background
"$BIN_DIR/clickhouse" server --config-file "$CONFIG_FILE" --daemon --pid-file "$DATA_DIR/clickhouse.pid"

# Wait for server
echo "Waiting for server..."
sleep 5
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    if "$BIN_DIR/clickhouse" client --query "SELECT 1" > /dev/null 2>&1; then
        break
    fi
    sleep 1
    RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
    echo "Server failed to start"
    # Print logs if available
    if [ -f "$DATA_DIR/clickhouse-server.err.log" ]; then
        echo "Error log:"
        tail -n 20 "$DATA_DIR/clickhouse-server.err.log"
    fi
    exit 1
fi

# Create table
echo "Creating table..."
"$BIN_DIR/clickhouse" client --query "CREATE TABLE IF NOT EXISTS hits (WatchID UInt64, JavaEnable UInt8, Title String, GoodEvent Int16, EventTime DateTime, EventDate Date, CounterID UInt32, ClientIP UInt32, RegionID UInt32, UserID UInt64, CounterClass Int8, OS UInt8, UserAgent UInt8, URL String, Referer String, IsRefresh UInt8, RefererCategoryID UInt16, RefererRegionID UInt32, URLCategoryID UInt16, URLRegionID UInt32, ResolutionWidth UInt16, ResolutionHeight UInt16, ResolutionDepth UInt8, FlashMajor UInt8, FlashMinor UInt8, FlashMinor2 String, NetMajor UInt8, NetMinor UInt8, UserAgentMajor UInt16, UserAgentMinor String, CookieEnable UInt8, JavascriptEnable UInt8, IsMobile UInt8, MobilePhone UInt8, MobilePhoneModel String, Params String, IPNetworkID UInt32, TraficSourceID Int8, SearchEngineID UInt16, SearchPhrase String, AdvEngineID UInt8, IsArtifical UInt8, WindowClientWidth UInt16, WindowClientHeight UInt16, ClientTimeZone Int16, ClientEventTime DateTime, SilverlightVersion1 UInt8, SilverlightVersion2 UInt8, SilverlightVersion3 UInt32, SilverlightVersion4 UInt16, PageCharset String, CodeVersion UInt32, IsLink UInt8, IsDownload UInt8, IsNotBounce UInt8, FUniqID UInt64, OriginalURL String, HID UInt32, IsOldCounter UInt8, IsEvent UInt8, IsParameter UInt8, DontCountHits UInt8, WithHash UInt8, HitColor String, LocalEventTime DateTime, Age UInt8, Sex UInt8, Income UInt8, Interests UInt16, Robotness UInt8, RemoteIP UInt32, WindowName Int32, OpenerName Int32, HistoryLength Int16, BrowserLanguage String, BrowserCountry String, SocialNetwork String, SocialAction String, HTTPError UInt16, SendTiming Int32, DNSTiming Int32, ConnectTiming Int32, ResponseStartTiming Int32, ResponseEndTiming Int32, FetchTiming Int32, SocialSourceNetworkID UInt8, SocialSourcePage String, ParamPrice Int64, ParamOrderID String, ParamCurrency String, ParamCurrencyID UInt16, GoalsReached String, OpenstatServiceName String, OpenstatCampaignID String, OpenstatAdID String, OpenstatSourceID String, UTMSource String, UTMMedium String, UTMCampaign String, UTMContent String, UTMTerm String, FromTag String, HasGCLID UInt8, RefererHash UInt64, URLHash UInt64, CLID UInt32) ENGINE = MergeTree() PARTITION BY toYYYYMM(EventDate) ORDER BY (CounterID, EventDate, intHash32(UserID)) SAMPLE BY intHash32(UserID) SETTINGS index_granularity = 8192"

# Check if data exists
COUNT=$("$BIN_DIR/clickhouse" client --query "SELECT count() FROM hits")
if [ "$COUNT" -eq "0" ]; then
    echo "Loading data..."
    "$BIN_DIR/clickhouse" client --query "INSERT INTO hits FROM INFILE '$DATA_DIR/hits.parquet' FORMAT Parquet"
    
    echo "Optimizing table..."
    "$BIN_DIR/clickhouse" client --query "OPTIMIZE TABLE hits FINAL"
else
    echo "Data already loaded (count: $COUNT)"
fi

# Stop server
echo "Stopping server..."
kill $(cat "$DATA_DIR/clickhouse.pid")
wait
echo "Setup complete."
