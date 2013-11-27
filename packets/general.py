from lxml import etree

class PolicyRequestGenerator(object):

	def __new__(self, domains):
		# create XML 
		root = etree.Element('cross-domain-policy')

		for domain, ports in domains.iteritems():
			child = etree.Element('allow-access-from')
			child.set('domain', domain)
			child.set('to-ports', ','.join(str(i) for i in ports))
		root.append(child)

		return etree.tostring(root)