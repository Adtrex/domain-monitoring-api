from rest_framework.decorators import api_view
from rest_framework.response import Response
from .nuclei_runner import run_nuclei_scan

@api_view(['GET'])
def test_endpoint(request):
    return Response({
        'message': 'API is working!',
        'status': 'success'
    })


@api_view(['GET'])
def nuclei_scan(request):
    """
    Run a Nuclei scan on a target domain via query param.
    Example: /api/scan?target=example.com&templates=ssl,cnvd
    """
    target = request.GET.get('target')
    templates = request.GET.get('templates', 'ssl')  # default template
    template_list = templates.split(',')

    if not target:
        return Response({'error': 'Target parameter is required'}, status=400)
    
    try:
        results = run_nuclei_scan(target, templates=template_list)
        return Response({'target': target, 'results': results})
    except Exception as e:
        return Response({'error': str(e)}, status=500)