from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
import logging
from src.config import Config


def setup_observability(service_name: str = "my-app"):
    """Sets up observability with tracing, metrics, and logging for the application.

    Args:
        service_name (str, optional): The name of the service. Defaults to "my-app".

    Returns:
        Tuple[trace.Tracer, metrics.Meter]: The tracer and meter instances.
    """
    resource = Resource.create({"service.name": service_name})

    # Tracing Setup
    trace_provider = TracerProvider(resource=resource)
    trace_exporter = OTLPSpanExporter(endpoint=Config.ALLOY_ENDPOINT, insecure=True)
    trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
    trace.set_tracer_provider(trace_provider)

    # Logging Setup
    logger_provider = LoggerProvider(resource=resource)
    log_exporter = OTLPLogExporter(endpoint=Config.ALLOY_ENDPOINT, insecure=True)
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
    set_logger_provider(logger_provider)

    # Python logging Handler
    handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Metrics Setup
    metric_exporter = OTLPMetricExporter(endpoint=Config.ALLOY_ENDPOINT, insecure=True)
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter, export_interval_millis=15000
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    return trace.get_tracer(__name__), metrics.get_meter(__name__)


def get_tracer(module_name: str):
    """Retrieves a tracer for the specified module.

    Args:
        module_name (str): The name of the module.

    Returns:
        trace.Tracer: The tracer instance for the module.
    """
    return trace.get_tracer(module_name)


def get_meter(module_name: str):
    """Retrieves a meter for the specified module.

    Args:
        module_name (str): The name of the module.

    Returns:
        metrics.Meter: The meter instance for the module.
    """
    return metrics.get_meter(module_name)
