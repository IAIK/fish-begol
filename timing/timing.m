#! /bin/octave -qf

arg_list = argv();

fiatshamir = zeros(nargin, 13);
bellargw   = zeros(nargin, 13);

for i = 1:nargin
  data = csvread(arg_list{i});
  numr = rows(data)/2;
  fiatshamir(i, :) = sum(data(1:numr,:));
  bellargw(i, :) = sum(data(numr+1:rows(data) ,:));
endfor

fiatshamir
bellargw


exit(0);
