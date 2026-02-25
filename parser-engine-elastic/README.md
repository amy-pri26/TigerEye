# DNP3 Parser Engine

Reads a `.pcap` file, extracts packet metadata, saves it as local JSON files, and indexes it into Elasticsearch for visualization in Grafana.

---

## Setup

**1. Navigate to the parser engine directory:**
```bash
cd parser-engine-elastic
```

**2. Install dependencies:**
```bash
py -m pip install scapy
py -m pip install "elasticsearch>=8.13,<9.0"
```

**3. Install Docker Desktop; Start Elasticsearch and Grafana via Docker Compose:**

Docker Desktop Link: https://www.docker.com/products/docker-desktop/

Once Docker Desktop is installed and running, run the below command to create the containers. Note that the docker-compose.yml file at the bottom of this README must be in the same project folder as the parser.py file before running this command.
```bash
docker compose up -d
```

Verify Elasticsearch is running:
```bash
curl http://localhost:9200
```

---

## Usage

Update the `.pcap` file path at the bottom of `parser.py` to match your local machine, then run:
```python
if __name__ == "__main__":
    engine = PcapEngine("dnp3_analysis_results")
    full_data = engine.pcap_read(r"path\to\your\file.pcap")  # update this path
```

```bash
py parser.py
```

Verify data was indexed:
```bash
curl http://localhost:9200/dnp3_packets/_count
```

---

## Grafana Dashboard

1. Go to `http://localhost:3000` and log in (`admin` / `admin`)
2. Go to **Connections → Data Sources → Add data source → Elasticsearch**
3. Set URL to `http://es_dnp3:9200`, Index name to `dnp3_packets`, Time field to `timestamp`
4. Click **Save & Test**
5. Create a new dashboard and add panels — set the time range to match your pcap capture date

> For the included DNP3 test capture, use `2004-10-11 12:00:00 UTC` to `2004-10-11 18:00:00 UTC`

---

## docker-compose.yml

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: es_dnp3
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  grafana:
    image: grafana/grafana:latest
    container_name: grafana_dnp3
    ports:
      - "3000:3000"
    depends_on:
      - elasticsearch

volumes:
  esdata:
```