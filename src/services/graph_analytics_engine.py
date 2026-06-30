import datetime
from sqlalchemy.orm import Session
from src.models.knowledge_graph import GraphEntity, GraphRelationship, GraphCommunity

class GraphAnalyticsEngine:
    def __init__(self, db: Session):
        self.db = db

    def detect_communities(self) -> list:
        self.db.query(GraphCommunity).delete()
        self.db.commit()

        entities = self.db.query(GraphEntity).all()
        comm_map = {}
        for ent in entities:
            comm_map.setdefault(ent.entity_type, []).append(ent)

        communities = []
        for name, nodes in comm_map.items():
            comm = GraphCommunity(
                community_name=f"Community-{name}",
                entity_count=len(nodes),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(comm)
            communities.append(comm)
        
        self.db.commit()
        return communities

    def discover_high_risk_clusters(self) -> list:
        results = []
        entities = self.db.query(GraphEntity).all()
        for ent in entities:
            conn_count = self.db.query(GraphRelationship).filter(
                (GraphRelationship.source_entity_id == ent.id) |
                (GraphRelationship.target_entity_id == ent.id)
            ).count()

            if conn_count > 1:
                results.append({
                    "entity_id": ent.id,
                    "name": ent.entity_name,
                    "type": ent.entity_type,
                    "centrality_score": conn_count
                })

        results.sort(key=lambda x: x["centrality_score"], reverse=True)
        return results
