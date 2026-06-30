import asyncio
import json
import logging
from typing import Dict, Any, Optional
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from src.config import settings

logger = logging.getLogger(__name__)

class KafkaProducerService:
    def __init__(self):
        self.producer: Optional[AIOKafkaProducer] = None
        self.enabled = True

    async def start(self):
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            await self.producer.start()
            logger.info("Kafka Producer started successfully.")
        except Exception as e:
            logger.error(f"Failed to start Kafka Producer: {e}. Running in degraded mode.")
            self.producer = None
            self.enabled = False

    async def stop(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka Producer stopped.")

    async def publish_event(self, topic: str, message: Dict[str, Any]):
        if not self.producer or not self.enabled:
            logger.warning(f"Kafka Producer not active. Simulating publish to {topic}: {message}")
            return
        try:
            await self.producer.send_and_wait(topic, message)
        except Exception as e:
            logger.error(f"Error publishing to topic {topic}: {e}")


class KafkaConsumerService:
    def __init__(self, topic: str, group_id: str):
        self.topic = topic
        self.group_id = group_id
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.enabled = True
        self._running = False

    async def start(self):
        try:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                group_id=self.group_id,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="earliest"
            )
            await self.consumer.start()
            self._running = True
            logger.info(f"Kafka Consumer started for topic {self.topic} under group {self.group_id}")
        except Exception as e:
            logger.error(f"Failed to start Kafka Consumer for {self.topic}: {e}")
            self.consumer = None
            self.enabled = False

    async def stop(self):
        self._running = False
        if self.consumer:
            await self.consumer.stop()
            logger.info(f"Kafka Consumer for {self.topic} stopped.")

    async def consume_messages(self, message_handler):
        """
        Skeleton method to consume and handle incoming threat feed stream messages.
        """
        if not self.consumer or not self.enabled:
            logger.warning(f"Kafka Consumer not active for {self.topic}.")
            return
        
        try:
            while self._running:
                # Wait for next batch or message
                msg_set = await self.consumer.getmany(timeout_ms=1000)
                for topic_partition, messages in msg_set.items():
                    for message in messages:
                        await message_handler(message.value)
        except Exception as e:
            logger.error(f"Error consuming messages from {self.topic}: {e}")


# Global producer instance for app routes and tasks
kafka_producer = KafkaProducerService()
