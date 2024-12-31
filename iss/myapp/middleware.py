from django.shortcuts import redirect
from django.conf import settings
from django.urls import resolve

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # List of URLs to exempt from authentication (like login, register, etc.)
        EXEMPT_URLS = ['/login/', '/register/', '/logout/']
        
        # Allow `/admin/` and all its subpaths to be exempt
        if request.path.startswith('/admin/'):
            return self.get_response(request)

        # Get the current URL's name
        url_name = resolve(request.path_info).url_name

        # Allow exempt URLs or already authenticated users
        if not request.user.is_authenticated and request.path not in EXEMPT_URLS:
            return redirect(settings.LOGIN_URL)  # Redirect to LOGIN_URL
        
        # Proceed with the normal request processing
        return self.get_response(request)
