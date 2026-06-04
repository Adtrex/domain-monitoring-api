from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import Domain, Asset, Scan, ScanAsset


class DomainScopedFilteringTests(APITestCase):
	def setUp(self):
		self.domain_a = Domain.objects.create(root_domain='example.com')
		self.domain_b = Domain.objects.create(root_domain='example.org')

		self.asset_a1 = Asset.objects.create(
			domain=self.domain_a,
			asset_type='subdomain',
			value='app.example.com',
			source='test',
		)
		self.asset_a2 = Asset.objects.create(
			domain=self.domain_a,
			asset_type='subdomain',
			value='api.example.com',
			source='test',
		)
		self.asset_b1 = Asset.objects.create(
			domain=self.domain_b,
			asset_type='subdomain',
			value='app.example.org',
			source='test',
		)

		self.scan_a = Scan.objects.create(scan_type='on-demand', status='completed')
		self.scan_b = Scan.objects.create(scan_type='on-demand', status='completed')

		ScanAsset.objects.create(scan=self.scan_a, asset=self.asset_a1)
		ScanAsset.objects.create(scan=self.scan_a, asset=self.asset_a2)
		ScanAsset.objects.create(scan=self.scan_b, asset=self.asset_b1)

	def test_assets_filtered_by_domain(self):
		url = reverse('asset-list')
		response = self.client.get(url, {'domain': self.domain_a.id})

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		returned_ids = {row['id'] for row in response.data.get('results', [])}
		self.assertEqual(returned_ids, {self.asset_a1.id, self.asset_a2.id})

	def test_assets_invalid_domain_returns_400(self):
		url = reverse('asset-list')
		response = self.client.get(url, {'domain': 'abc'})

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_scans_filtered_by_domain_id(self):
		url = reverse('scan-list')
		response = self.client.get(url, {'domain_id': self.domain_a.id})

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		returned_ids = {row['id'] for row in response.data.get('results', [])}
		self.assertEqual(returned_ids, {self.scan_a.id})

	def test_scans_invalid_domain_returns_400(self):
		url = reverse('scan-list')
		response = self.client.get(url, {'domain_id': 'invalid'})

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
