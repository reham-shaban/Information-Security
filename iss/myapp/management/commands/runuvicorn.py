import uvicorn
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Run the Django project with Uvicorn'

    def add_arguments(self, parser):
        parser.add_argument('--workers', type=int, default=4, help='Number of workers')
        parser.add_argument('--host', type=str, default='0.0.0.0', help='Host address')
        parser.add_argument('--port', type=int, default=8000, help='Port number')

    def handle(self, *args, **options):
        uvicorn.run(
            "iss.asgi:application",  # Replace 'myapp' with your project name
            workers=options['workers'],
            host=options['host'],
            port=options['port'],
            lifespan="off",  # Disable lifespan protocol
        )

