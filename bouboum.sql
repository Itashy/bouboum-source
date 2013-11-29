CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` text NOT NULL,
  `password` text NOT NULL,
  `shopnuts` int(11) NOT NULL,
  `look` text,
  `rounds` int(11) NOT NULL,
  `kills` int(11) NOT NULL,
  `death` int(11) NOT NULL,
  `gamewon` int(11) NOT NULL,
  `roundswon` int(11) NOT NULL,
  `shopitems` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;