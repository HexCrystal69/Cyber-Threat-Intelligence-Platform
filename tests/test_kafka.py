import pytest
from unittest.mock import patch, AsyncMock
from src.kafka_client import KafkaProducerService, KafkaConsumerService, kafka_producer

@pytest.mark.asyncio
async def test_kafka_producer_publish_success():
    producer_service = KafkaProducerService()
    
    mock_producer = AsyncMock()
    mock_producer.send_and_wait = AsyncMock()
    producer_service.producer = mock_producer
    
    event_data = {"test": "data"}
    await producer_service.publish_event("threat-feed-events", event_data)
    
    mock_producer.send_and_wait.assert_called_once_with("threat-feed-events", event_data)

@pytest.mark.asyncio
async def test_kafka_producer_degraded_state_handling():
    producer_service = KafkaProducerService()
    # If starting fails, it runs in degraded mode (disabled=True gets flipped)
    with patch("aiokafka.AIOKafkaProducer.start", side_effect=Exception("Connection refused")):
        await producer_service.start()
        assert producer_service.producer is None
        assert producer_service.enabled is False

@pytest.mark.asyncio
async def test_kafka_consumer_start_stop():
    consumer_service = KafkaConsumerService("threat-feed-events", "test-group")
    with patch("aiokafka.AIOKafkaConsumer.start", new_callable=AsyncMock) as mock_start, \
         patch("aiokafka.AIOKafkaConsumer.stop", new_callable=AsyncMock) as mock_stop:
        
        await consumer_service.start()
        assert consumer_service._running is True
        
        await consumer_service.stop()
        assert consumer_service._running is False

@pytest.mark.asyncio
async def test_kafka_consumer_consume_messages():
    consumer_service = KafkaConsumerService("threat-feed-events", "test-group")
    
    mock_consumer = AsyncMock()
    # Mock getmany to return a dummy message batch
    mock_msg = AsyncMock()
    mock_msg.value = {"ioc_id": "123", "indicator": "1.1.1.1"}
    
    # We simulate a one-shot consume loop by raising Exception to break loop or patch self._running
    mock_consumer.getmany = AsyncMock(return_value={None: [mock_msg]})
    consumer_service.consumer = mock_consumer
    consumer_service._running = True

    handled_messages = []
    async def dummy_handler(msg):
        handled_messages.append(msg)
        # Stop loop after first message
        consumer_service._running = False

    await consumer_service.consume_messages(dummy_handler)
    assert len(handled_messages) == 1
    assert handled_messages[0]["indicator"] == "1.1.1.1"
