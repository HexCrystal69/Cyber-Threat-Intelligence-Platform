import datetime
import json
from sqlalchemy.orm import Session
from src.models.knowledge_graph import GraphEntity, GraphRelationship, GraphSnapshot, GraphPathCache
from src.models.ioc import IOC
from src.models.campaign import ThreatCampaign
from src.models.actor import ThreatActor
from src.utils.metrics import graph_nodes_total, graph_edges_total

class KnowledgeGraphEngine:
    def __init__(self, db: Session):
        self.db = db

    def rebuild_graph(self) -> dict:
        self.db.query(GraphRelationship).delete()
        self.db.query(GraphEntity).delete()
        self.db.commit()

        actors = self.db.query(ThreatActor).all()
        actor_nodes = {}
        for a in actors:
            node = GraphEntity(
                entity_type="Actor",
                entity_name=a.name,
                source_table="threat_actors",
                source_record_id=str(a.id),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(node)
            self.db.commit()
            actor_nodes[a.id] = node.id

        campaigns = self.db.query(ThreatCampaign).all()
        campaign_nodes = {}
        for c in campaigns:
            node = GraphEntity(
                entity_type="Campaign",
                entity_name=c.name,
                source_table="threat_campaigns",
                source_record_id=str(c.id),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(node)
            self.db.commit()
            campaign_nodes[c.id] = node.id

        iocs = self.db.query(IOC).all()
        ioc_nodes = {}
        for ioc in iocs:
            node = GraphEntity(
                entity_type="IOC",
                entity_name=ioc.indicator_value,
                source_table="iocs",
                source_record_id=str(ioc.id),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(node)
            self.db.commit()
            ioc_nodes[ioc.id] = node.id

        edge_count = 0
        for c_id, c_node_id in campaign_nodes.items():
            for a_id, a_node_id in actor_nodes.items():
                rel = GraphRelationship(
                    source_entity_id=a_node_id,
                    target_entity_id=c_node_id,
                    relationship_type="attributed-to",
                    weight=1.0,
                    created_at=datetime.datetime.utcnow()
                )
                self.db.add(rel)
                edge_count += 1

        for i_id, i_node_id in ioc_nodes.items():
            for c_node_id in campaign_nodes.values():
                rel = GraphRelationship(
                    source_entity_id=i_node_id,
                    target_entity_id=c_node_id,
                    relationship_type="indicates",
                    weight=0.8,
                    created_at=datetime.datetime.utcnow()
                )
                self.db.add(rel)
                edge_count += 1

        self.db.commit()

        node_count = len(actor_nodes) + len(campaign_nodes) + len(ioc_nodes)
        snap = GraphSnapshot(
            node_count=node_count,
            edge_count=edge_count,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(snap)
        self.db.commit()

        graph_nodes_total.inc(node_count)
        graph_edges_total.inc(edge_count)

        return {"nodes": node_count, "edges": edge_count}

    def discover_path(self, start_entity_id: int, target_entity_id: int) -> list:
        cache = self.db.query(GraphPathCache).filter(
            GraphPathCache.source_entity_id == start_entity_id,
            GraphPathCache.target_entity_id == target_entity_id
        ).first()
        if cache:
            return json.loads(cache.path_json)

        path = [start_entity_id, target_entity_id]
        
        new_cache = GraphPathCache(
            source_entity_id=start_entity_id,
            target_entity_id=target_entity_id,
            path_json=json.dumps(path),
            hop_count=len(path) - 1,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(new_cache)
        self.db.commit()
        return path
