from django.shortcuts import render

def frontend_view(request):
    """Serve the frontend index.html file"""
    return render(request, 'index.html')

