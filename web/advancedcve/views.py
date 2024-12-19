from django.shortcuts import render


def index(request):
    """
        Index page of AdvancedCVE !
    """
    return render(request, 'advancedcve/index.html')