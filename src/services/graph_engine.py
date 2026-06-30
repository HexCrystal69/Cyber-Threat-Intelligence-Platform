import datetime
import json
import logging
from sqlalchemy.orm import Session
from src.models.ioc import IOC
from src.models.relationship import IOCRelationship
from src.models.campaign import CampaignIOC, ThreatCampaign
from src.models.actor import ActorCampaign, ThreatActor
from src.models.graph import ThreatGraphSnapshot

logger = logging.getLogger(__name__)

class GraphEngine:
    def __init__(self, db: Session):
        self.db = db

    def traverse_graph(self, start_ioc_id: int, max_depth: int = 2) -> dict:
        """
        Traverse the threat graph starting from a specific IOC up to a max_depth using BFS.
        Returns a dict of nodes and edges.
        """
        visited_iocs = set()
        queue = [(start_ioc_id, 0)]  # (ioc_id, current_depth)
        nodes = []
        edges = []

        # Find starting IOC
        start_ioc = self.db.query(IOC).filter(IOC.id == start_ioc_id).first()
        if not start_ioc:
            return {"nodes": [], "edges": []}

        nodes.append({
            "id": f"ioc_{start_ioc.id}",
            "type": "IOC",
            "label": start_ioc.indicator_value,
            "indicator_type": start_ioc.indicator_type,
            "severity": start_ioc.severity
        })
        visited_iocs.add(start_ioc_id)

        while queue:
            curr_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            # Find relationships
            relations = self.db.query(IOCRelationship).filter(
                (IOCRelationship.source_ioc_id == curr_id) | 
                (IOCRelationship.target_ioc_id == curr_id)
            ).all()

            for r in relations:
                neighbor_id = r.target_ioc_id if r.source_ioc_id == curr_id else r.source_ioc_id
                
                # Add relationship edge
                edge_id = f"rel_{r.id}"
                edge_obj = {
                    "id": edge_id,
                    "source": f"ioc_{r.source_ioc_id}",
                    "target": f"ioc_{r.target_ioc_id}",
                    "type": r.relationship_type,
                    "strength": r.relationship_strength
                }
                if edge_obj not in edges:
                    edges.append(edge_obj)

                # Add neighbor node if not visited
                if neighbor_id not in visited_iocs:
                    neighbor = self.db.query(IOC).filter(IOC.id == neighbor_id).first()
                    if neighbor:
                        nodes.append({
                            "id": f"ioc_{neighbor.id}",
                            "type": "IOC",
                            "label": neighbor.indicator_value,
                            "indicator_type": neighbor.indicator_type,
                            "severity": neighbor.severity
                        })
                        visited_iocs.add(neighbor_id)
                        queue.append((neighbor_id, depth + 1))

            # Find Campaign connections
            camp_iocs = self.db.query(CampaignIOC).filter(CampaignIOC.ioc_id == curr_id).all()
            for ci in camp_iocs:
                camp = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == ci.campaign_id).first()
                if camp:
                    camp_node = {
                        "id": f"campaign_{camp.id}",
                        "type": "CAMPAIGN",
                        "label": camp.name,
                        "severity": camp.severity
                    }
                    if camp_node not in nodes:
                        nodes.append(camp_node)
                    
                    camp_edge = {
                        "id": f"camp_edge_{ci.id}",
                        "source": f"ioc_{curr_id}",
                        "target": f"campaign_{camp.id}",
                        "type": "CAMPAIGN_MEMBER",
                        "strength": "STRONG"
                    }
                    if camp_edge not in edges:
                        edges.append(camp_edge)

                    # Trace Campaign to Threat Actor
                    actor_camps = self.db.query(ActorCampaign).filter(ActorCampaign.campaign_id == camp.id).all()
                    for ac in actor_camps:
                        actor = self.db.query(ThreatActor).filter(ThreatActor.id == ac.actor_id).first()
                        if actor:
                            actor_node = {
                                "id": f"actor_{actor.id}",
                                "type": "ACTOR",
                                "label": actor.name,
                                "country": actor.country
                            }
                            if actor_node not in nodes:
                                nodes.append(actor_node)

                            actor_edge = {
                                "id": f"actor_edge_{ac.id}",
                                "source": f"campaign_{camp.id}",
                                "target": f"actor_{actor.id}",
                                "type": "ATTRIBUTED_TO",
                                "strength": "STRONG"
                            }
                            if actor_edge not in edges:
                                edges.append(actor_edge)

        return {"nodes": nodes, "edges": edges}

    def generate_global_snapshot(self) -> ThreatGraphSnapshot:
        """
        Serialize all active nodes and edges to generate a global snapshot record.
        """
        iocs = self.db.query(IOC).all()
        relations = self.db.query(IOCRelationship).all()
        campaigns = self.db.query(ThreatCampaign).all()
        camp_iocs = self.db.query(CampaignIOC).all()
        actors = self.db.query(ThreatActor).all()
        actor_camps = self.db.query(ActorCampaign).all()

        nodes = []
        edges = []

        for ioc in iocs:
            nodes.append({
                "id": f"ioc_{ioc.id}",
                "type": "IOC",
                "label": ioc.indicator_value
            })

        for c in campaigns:
            nodes.append({
                "id": f"campaign_{c.id}",
                "type": "CAMPAIGN",
                "label": c.name
            })

        for a in actors:
            nodes.append({
                "id": f"actor_{a.id}",
                "type": "ACTOR",
                "label": a.name
            })

        for r in relations:
            edges.append({
                "source": f"ioc_{r.source_ioc_id}",
                "target": f"ioc_{r.target_ioc_id}",
                "type": r.relationship_type
            })

        for ci in camp_iocs:
            edges.append({
                "source": f"ioc_{ci.ioc_id}",
                "target": f"campaign_{ci.campaign_id}",
                "type": "CAMPAIGN_MEMBER"
            })

        for ac in actor_camps:
            edges.append({
                "source": f"campaign_{ac.campaign_id}",
                "target": f"actor_{ac.actor_id}",
                "type": "ATTRIBUTED_TO"
            })

        graph_data = {"nodes": nodes, "edges": edges}
        
        snapshot = ThreatGraphSnapshot(
            node_count=len(nodes),
            edge_count=len(edges),
            graph_json=graph_data
        )
        self.db.add(snapshot)
        self.db.commit()
        self.db.refresh(snapshot)
        return snapshot
