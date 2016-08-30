#! /bin/octave -qf

arg_list = argv();

fiatshamir = zeros(nargin, 13);
bellargw   = zeros(nargin, 13);

for i = 1:nargin
  data = csvread(arg_list{i});
  numr = rows(data)/2;
  fiatshamir(i, :) = sum(data(1:numr,:),1)/numr;
  bellargw(i, :) = sum(data(numr+1:rows(data) ,:),1)/numr;
endfor

fs_sum = zeros(nargin, 3);
bg_sum = zeros(nargin, 3);


fs_sum(:,1) = sum(fiatshamir(:,1:3), 2);
bg_sum(:,1) = sum(bellargw(:,1:3), 2);
fs_sum(:,2) = sum(fiatshamir(:,4:8), 2);
bg_sum(:,2) = sum(bellargw(:,4:8), 2);
fs_sum(:,3) = sum(fiatshamir(:,9:13), 2);
bg_sum(:,3) = sum(bellargw(:,9:13), 2);

close all;
plot(1:nargin, fs_sum(:,1), 1:nargin, fs_sum(:,2), 1:nargin, fs_sum(:,3));
print('test.png');


